<#
    .SYNOPSIS
        Exports GraphKit operation results as CSV, JSON, Markdown, or vault evidence.

    .DESCRIPTION
        Consumes either canonical GraphKit.OperationResult envelopes (from
        Invoke-GraphOperation or Invoke-GraphBatch) or raw data rows, and writes
        them out in the requested shape. Csv and Markdown export Data rows only;
        Json preserves the full envelope (Outcome, Certainty, Telemetry, and
        Provenance) when given envelopes, with telemetry deep-redacted so bearer
        tokens, secrets, and raw query values can never reach the file.
        VaultEvidence writes raw rows under the report root (outside the vault)
        and a summary evidence page under the evidence root, built from a summary
        DTO whose fields are allowlisted. An Indeterminate result is refused
        unless -Force is supplied, because filing an uncertain outcome as
        evidence is exactly the error the certainty field exists to prevent.

    .EXAMPLE
        Export-GraphResult -Result $result -As Json -Path ./exports

        Writes the full envelope, including Outcome, Certainty, sanitized
        Telemetry, and Provenance, to a JSON file under ./exports.

    .EXAMPLE
        Export-GraphResult -Result $rows -As Csv -Path ./exports -Name managedDevices

        Writes only the Data rows to managedDevices.csv under ./exports.

    .EXAMPLE
        Export-GraphResult -Result $result -As VaultEvidence -ProfileId contoso -Kind lab

        Files raw rows under the report root and a summary evidence page, log,
        and index under the evidence root for the contoso profile.

    .PARAMETER Result
        The operation result to export: one or more GraphKit.OperationResult
        envelopes, an array of envelopes, or an array of raw data rows. Envelopes
        are unwrapped automatically; Data rows feed Csv and Markdown, while Json
        keeps the full envelope.

    .PARAMETER As
        The export shape: Csv, Json, Markdown, or VaultEvidence. Csv and
        Markdown emit Data rows only, Json preserves envelopes, and VaultEvidence
        writes raw rows plus a vault summary page.

    .PARAMETER Path
        The directory to write the export file into for Csv, Json, and Markdown.
        The file is named from -Name (or 'graph-result') plus the format's
        extension. Not used by VaultEvidence, which writes under the two roots.

    .PARAMETER ProfileId
        The canonical profile identifier used to build report and evidence paths
        for VaultEvidence. It is validated as path-safe and is the only value that
        ever influences an output path.

    .PARAMETER Name
        The display name used as the file base name for Csv/Json/Markdown, or as
        the customer tag in the evidence frontmatter for VaultEvidence. It is
        never used as a path segment.

    .PARAMETER Kind
        The profile taxonomy for vault evidence: customer, lab, or internal. For
        customer, the frontmatter customers list contains -Name; otherwise it is
        empty.

    .PARAMETER Force
        Override the refusal to export a result whose Certainty is Indeterminate.
        Without this switch an Indeterminate result raises an actionable error.

    .PARAMETER NoRedact
        Write rows exactly as the service returned them, including properties the operation
        declared as secret-bearing.

        By default EVERY format - Csv, Json, Markdown and the VaultEvidence rows.json - replaces
        those properties with '[REDACTED]'. What gets redacted is DECLARED by the operation
        descriptor (its SensitiveProperties), not guessed from property names: name-guessing was
        measured against real responses and redacted nine DeviceCompliancePolicy password-policy
        settings while missing scriptContent entirely, which produces an export that reads as
        sanitised and is not.

        Use this when the actual value is the point - an investigation turning on a specific
        setting, or evidence that must be byte-exact. It writes customer secrets to disk in the
        clear, so it should be a decision rather than a habit.

        Rows passed without an envelope carry no declaration, so nothing can be redacted; that
        case warns rather than passing silently.

    .PARAMETER VaultAdapter
        An optional scriptblock invoked with the summary DTO (plus EvidenceRoot
        and ReportRoot) after the filesystem evidence write. Use it to capture
        evidence or route it elsewhere; the filesystem write is the default.

    .PARAMETER ReportRoot
        The base directory for raw rows in VaultEvidence mode. Defaults to
        ~/repo/report-exports. Raw rows are written to <ReportRoot>/<ProfileId>/.

    .PARAMETER EvidenceRoot
        The base directory for the vault summary page, log, and index. Defaults
        to the cdw-kb/evidence directory inside the Obsidian vault. Files are
        written to <EvidenceRoot>/<ProfileId>/.
#>
function Export-GraphResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowNull()]
        $Result,

        [Parameter(Mandatory, Position = 1)]
        [ValidateSet('Csv', 'Json', 'Markdown', 'VaultEvidence')]
        [string] $As,

        [Parameter(Position = 2)]
        [string] $Path,

        [Parameter()]
        [string] $ProfileId,

        [Parameter()]
        [string] $Name,

        [Parameter()]
        [ValidateSet('customer', 'lab', 'internal')]
        [string] $Kind,

        [Parameter()]
        [switch] $Force,

        # Writes rows exactly as the service returned them, including any property the
        # operation declared as secret-bearing. Raw evidence is a legitimate need - an
        # investigation may turn on the actual value - so the capability exists, but it has to
        # be asked for. Without it every format redacts what the descriptor declared.
        [Parameter()]
        [switch] $NoRedact,

        [Parameter()]
        [scriptblock] $VaultAdapter,

        [Parameter()]
        [string] $ReportRoot,

        [Parameter()]
        [string] $EvidenceRoot
    )

    # Deep redaction for JSON output: rebuild the object graph, replacing the
    # value of any property whose NAME matches a credential or query-value
    # pattern with a literal placeholder. Telemetry is already sanitized at the
    # source; this is belt-and-braces so a bearer, secret, or raw query value can
    # never reach a JSON export even if a future telemetry field regresses.
    function ConvertTo-GraphSanitizedObject {
        [CmdletBinding()]
        param(
            [AllowNull()]
            $InputObject,
            [int] $Depth = 0
        )

        # A DENYLIST, and the docstring above claims secrets can never reach the file - so every
        # term missing from it is a hole in a stated guarantee. Added after review found ApiKey,
        # ClientAssertion and Thumbprint written verbatim: this module's own vocabulary is full of
        # pfx/thumbprint/assertion, so those were the likeliest fields to appear and the least
        # likely to be caught.
        # NOTE this sanitiser runs over the WHOLE envelope, .Data included - so every term added
        # here also name-matches against real row data. That is the over-redaction trap the
        # descriptor-declared redaction exists to avoid: a pattern written for the envelope once
        # matched nine innocuous DeviceCompliancePolicy password* settings.
        #
        # So the additions are deliberately narrow. 'assertion', 'thumbprint', 'pfx', 'apikey',
        # 'jwt' and 'passphrase' are credential vocabulary with no benign meaning in Intune row
        # data. A bare 'key' and 'cert*' were tried and REJECTED: they would redact
        # certificateExpirationDate and any settings row with a 'key' field, which is worse than
        # the hole they close.
        $sensitivePattern = '(?i)(token|secret|bearer|password|authorization|credential|assertion|thumbprint|\bpfx\b|\bapi[-_]?key\b|\bjwt\b|passphrase|\$filter|\$search|\bquery\b|\bsig\b|signature)'

        if ($Depth -gt 20 -or $null -eq $InputObject) {
            return $null
        }

        $type = $InputObject.GetType()

        if ($type.IsPrimitive -or $type.IsEnum -or $InputObject -is [string] -or
            $InputObject -is [decimal] -or $InputObject -is [datetime] -or
            $InputObject -is [datetimeoffset] -or $InputObject -is [guid] -or
            $InputObject -is [uri]) {
            return $InputObject
        }

        if ($InputObject -is [System.Collections.IDictionary]) {
            $dict = [ordered]@{}
            foreach ($key in @($InputObject.Keys)) {
                if ("$key" -match $sensitivePattern) {
                    $dict[$key] = '[REDACTED]'
                } else {
                    $dict[$key] = ConvertTo-GraphSanitizedObject -InputObject $InputObject[$key] -Depth ($Depth + 1)
                }
            }
            return [pscustomobject] $dict
        }

        if ($InputObject -is [System.Collections.IEnumerable]) {
            $list = [System.Collections.Generic.List[object]]::new()
            foreach ($item in $InputObject) {
                $list.Add((ConvertTo-GraphSanitizedObject -InputObject $item -Depth ($Depth + 1)))
            }
            return $list.ToArray()
        }

        $dict = [ordered]@{}
        foreach ($prop in $InputObject.PSObject.Properties) {
            if ($prop.Name -match $sensitivePattern) {
                $dict[$prop.Name] = '[REDACTED]'
            } else {
                $dict[$prop.Name] = ConvertTo-GraphSanitizedObject -InputObject $prop.Value -Depth ($Depth + 1)
            }
        }
        return [pscustomobject] $dict
    }

    # --- Normalize input: envelopes vs raw rows ----------------------------
    $items = @($Result)

    $isEnvelopeInput = $false
    $envelopes = [System.Collections.Generic.List[object]]::new()
    $rows = [System.Collections.Generic.List[object]]::new()

    foreach ($item in $items) {
        if ($null -eq $item) { continue }

        $isEnvelope = $false
        if ($item.PSObject.TypeNames -contains 'GraphKit.OperationResult') {
            $isEnvelope = $true
        } else {
            $names = $item.PSObject.Properties.Name
            if ($names -contains 'Outcome' -and $names -contains 'Certainty') {
                $isEnvelope = $true
            }
        }

        if ($isEnvelope) {
            $isEnvelopeInput = $true
            $envelopes.Add($item)
            foreach ($row in @($item.Data)) {
                if ($null -ne $row) {
                    $rows.Add($row)
                }
            }
        } else {
            $rows.Add($item)
        }
    }

    # --- Redact descriptor-declared secret-bearing properties ---------------
    # The declaration rides on the envelope's provenance because Export-GraphResult never sees
    # a descriptor. Guessing by property name instead was measured and rejected: the envelope
    # sanitiser's pattern redacts nine DeviceCompliancePolicy settings while missing
    # scriptContent, which produces an export that reads as sanitised and is not.
    if (-not $NoRedact) {
        $declared = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($envelope in $envelopes) {
            $envelopeProvenance = $envelope.Provenance
            if ($null -ne $envelopeProvenance -and $envelopeProvenance.ContainsKey('SensitiveProperties')) {
                foreach ($declaration in @($envelopeProvenance['SensitiveProperties'])) {
                    $null = $declared.Add([string] $declaration)
                }
            }
        }

        if ($declared.Count -gt 0) {
            $redacted = [System.Collections.Generic.List[object]]::new()
            foreach ($row in $rows) {
                $redacted.Add((ConvertTo-GraphRedactedRow -Row $row -SensitiveProperties @($declared)))
            }
            $rows = $redacted

            # The Json branch serialises the ENVELOPES when given envelope input, and an
            # envelope's .Data is the original row set - so redacting $rows alone would leave
            # Json exporting the secrets while Csv, Markdown and rows.json were clean. Rebuild
            # the envelopes over redacted Data. Copies, not mutations: the caller's envelope is
            # still theirs to use.
            if ($isEnvelopeInput) {
                $redactedEnvelopes = [System.Collections.Generic.List[object]]::new()
                foreach ($envelope in $envelopes) {
                    $clone = [ordered]@{}
                    foreach ($property in $envelope.PSObject.Properties) {
                        $clone[$property.Name] = if ($property.Name -eq 'Data') {
                            @(@($property.Value) | Where-Object { $null -ne $_ } | ForEach-Object {
                                    ConvertTo-GraphRedactedRow -Row $_ -SensitiveProperties @($declared)
                                })
                        }
                        else { $property.Value }
                    }
                    $copy = [pscustomobject] $clone
                    $copy.PSObject.TypeNames.Insert(0, 'GraphKit.OperationResult')
                    $redactedEnvelopes.Add($copy)
                }
                $envelopes = $redactedEnvelopes
            }
        }
        elseif ($isEnvelopeInput -and $rows.Count -gt 0) {
            # An envelope with no declaration is NOT the same as raw rows, and it used to be
            # silent because the branch below is gated on -not $isEnvelopeInput. The operation
            # was identified; its descriptor simply declares no SensitiveProperties. That is
            # usually correct - most operations return no secrets - but it is indistinguishable
            # from an operation whose declaration was forgotten, and the export reads as
            # sanitised either way. Name it once so the reader can tell which they are holding.
            # DETECT, do not redact. The sanitiser no longer name-matches .Data, because doing so
            # replaced whole containers - 'passwordCredentials' matched 'credential' and took
            # endDateTime and keyId with it - and a declaration the export can override is not
            # authoritative. But dropping the net silently would trade one failure for another,
            # so the names are still checked and only WARNED about.
            #
            # This fires on the case that actually matters: row data that looks secret-bearing
            # from an operation that declares nothing. It stays quiet for the ~60 operations
            # returning no secrets, so it does not become noise people learn to suppress. The
            # remedy it names is the descriptor, which is where the fix belongs.
            $suspect = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($r in $rows) {
                $names = if ($r -is [System.Collections.IDictionary]) { @($r.Keys) } else { @($r.PSObject.Properties.Name) }
                foreach ($n in $names) {
                    if ([string] $n -match '(?i)(secrettext|\bsecret\b|accesstoken|\btoken\b|assertion|passwordhash|privatekey)') {
                        $null = $suspect.Add([string] $n)
                    }
                }
            }
            if ($suspect.Count -gt 0) {
                Write-Warning ("Export-GraphResult: '{0}' declares no SensitiveProperties, but the rows carry {1} - which look secret-bearing and are being exported in the clear. Declare them on the operation descriptor; -NoRedact is not the fix." -f $Name, (($suspect | Sort-Object) -join ', '))
            }
            else {
                Write-Verbose 'Export-GraphResult: the operation declared no SensitiveProperties, so nothing was redacted.'
            }
        }
        elseif (-not $isEnvelopeInput -and $rows.Count -gt 0) {
            # Raw rows carry no provenance, so nothing can be declared and nothing is redacted.
            # Saying so matters: a silent no-op here looks identical to a successful redaction,
            # which is the false-sense-of-safety this whole change exists to remove.
            Write-Warning 'Exporting raw rows: no operation declaration is available, so no properties were redacted. Pass an envelope from Get-GraphObject/Invoke-GraphOperation if the rows may carry secrets.'
        }
    }

    # --- Refuse Indeterminate without -Force -------------------------------
    if ($isEnvelopeInput -and -not $Force) {
        $indeterminate = 0
        foreach ($envelope in $envelopes) {
            if ("$($envelope.Certainty)" -eq 'Indeterminate') {
                $indeterminate++
            }
        }

        if ($indeterminate -gt 0) {
            throw "Refusing to export $indeterminate result(s) with 'Indeterminate' certainty. An uncertain outcome (for example a write whose commit status is unknown) must never be filed as evidence by default; re-run with -Force to override."
        }
    }

    # --- File-shaped exports (Csv / Json / Markdown) ------------------------
    if ($As -in @('Csv', 'Json', 'Markdown')) {
        if ([string]::IsNullOrWhiteSpace($Path)) {
            throw "-As $As requires -Path: the directory to write the export file into."
        }

        $outputDir = [System.IO.Path]::GetFullPath($Path)
        if (-not (Test-Path -LiteralPath $outputDir -PathType Container)) {
            $null = New-Item -ItemType Directory -Path $outputDir -Force
        }

        $baseName = if ([string]::IsNullOrWhiteSpace($Name)) { 'graph-result' } else { $Name }
        $extension = switch ($As) {
            'Csv' { 'csv' }
            'Json' { 'json' }
            'Markdown' { 'md' }
        }
        $filePath = Join-Path $outputDir "$baseName.$extension"

        # -Name is free text and is concatenated into a path, so it is verified rather
        # than trusted - the same rule the raw-export path below already follows. A Name
        # containing a separator or '..' would otherwise write outside -Path, and Name is
        # exactly the kind of value that gets built from a report title or profile rather
        # than typed literally.
        if (-not (Test-GraphPathContainment -Root $outputDir -Candidate $filePath)) {
            throw (
                "Refusing to write outside -Path: the resolved export file '{0}' is not beneath '{1}'. " -f $filePath, $outputDir
            ) + "Check -Name ('$baseName') for path separators or '..'."
        }

        switch ($As) {
            'Csv' {
                # Neutralise spreadsheet formula injection. A cell beginning '=', '+', '-' or
                # '@' is executed by Excel on open, and Graph data is partly attacker-influenced
                # at the customer - users can rename their own devices in many Intune
                # configurations, and these reports are shared WITH customers.
                #
                # Only strings are prefixed. A numeric -5 is not a formula risk, and prefixing
                # it would corrupt every negative number in the report. Only Csv is treated:
                # JSON and Markdown do not execute cell formulas.
                # Rows arrive as HASHTABLES when the transport parsed JSON with -AsHashtable,
                # and $row.PSObject.Properties on a hashtable enumerates Count/Keys/Values -
                # not the entries. Reading the wrong member set silently drops every real
                # column: caught by exporting live compliance policies and finding
                # passwordRequired missing where plain Export-Csv produces it.
                $csvRows = foreach ($row in $rows) {
                    $cells = [ordered]@{}
                    $entries = if ($row -is [System.Collections.IDictionary]) {
                        @($row.Keys | ForEach-Object { [pscustomobject]@{ Name = $_; Value = $row[$_] } })
                    }
                    else {
                        @($row.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Value = $_.Value } })
                    }

                    foreach ($entry in $entries) {
                        $value = $entry.Value
                        # Test the first NON-WHITESPACE character. Excel and LibreOffice strip a
                        # leading tab, CR or space before parsing, so "<TAB>=cmd|calc" executes
                        # while looking harmless here - checking $value[0] let all three through.
                        # Verified: <TAB>, <CR> and space prefixes were all written unprefixed.
                        $firstMeaningful = if ($value -is [string]) { ($value -replace '^[\s\u0000-\u001F]+', '') } else { '' }
                        if ($value -is [string] -and $firstMeaningful.Length -gt 0 -and $firstMeaningful[0] -in @('=', '+', '-', '@')) {
                            $cells[$entry.Name] = "'" + $value
                        }
                        else {
                            $cells[$entry.Name] = $value
                        }
                    }
                    [pscustomobject] $cells
                }
                @($csvRows) | Export-Csv -LiteralPath $filePath -NoTypeInformation -Encoding utf8
            }

            'Json' {
                $toSerialize = if ($isEnvelopeInput) { $envelopes.ToArray() } else { $rows.ToArray() }
                # AGENTS.md:127 - never export tenant or client ids. Provenance carried the full
                # tenant GUID verbatim into every JSON export, and these files are shared with
                # customers.
                #
                # Scrubbed BEFORE the sanitiser, not after: the sanitiser reshapes the envelope
                # and the Provenance is no longer reachable as a property afterwards - the first
                # attempt looked correct, ran without error, and left the GUID in the file.
                #
                # Done here rather than by adding 'tenant' to the name pattern, because that
                # pattern also sees row data and a device or policy row can legitimately carry a
                # tenantId the reader needs.  ProfileId is deliberately kept: it says which
                # profile produced the export without being a directory identifier.
                foreach ($item in @($toSerialize)) {
                    if ($null -eq $item) { continue }
                    $prov = $null
                    if ($item -is [System.Collections.IDictionary]) { $prov = $item['Provenance'] }
                    elseif ($item.PSObject.Properties['Provenance']) { $prov = $item.PSObject.Properties['Provenance'].Value }
                    if ($prov -isnot [System.Collections.IDictionary]) { continue }
                    foreach ($k in @($prov.Keys)) {
                        if ($k -in @('TenantId', 'ActualTenantId', 'ClientId', 'AppId') -and
                            -not [string]::IsNullOrWhiteSpace([string] $prov[$k])) {
                            $prov[$k] = '[REDACTED]'
                        }
                    }
                }

                # The sanitiser must NOT touch .Data when a declaration governs it.
                #
                # It name-matches 'credential|token|secret|...' across whatever it is given, and
                # it was being given the whole envelope - so `passwordCredentials` came back
                # [REDACTED] on an application or service-principal export REGARDLESS of the
                # descriptor, taking endDateTime and keyId with it. A credential-hygiene check
                # reads exactly that metadata and never the secret, so the export was useless to
                # it. Neither a narrower dotted declaration nor -NoRedact escaped it, because
                # neither is what was redacting.
                #
                # That is the precise failure descriptor-declared redaction was introduced to
                # end: a pattern written for envelope TELEMETRY applied to row DATA, the same
                # shape as the nine innocuous DeviceCompliancePolicy password* settings it once
                # flagged. Two redaction layers disagreeing means the declared one is not
                # authoritative, and a declaration nobody can rely on is worse than none.
                #
                # So: for an ENVELOPE, sanitise everything EXCEPT Data - Telemetry and Provenance
                # are where URIs, filters and tokens actually appear - and let the descriptor's
                # SensitiveProperties govern Data, which has already been applied above.
                #
                # RAW rows keep the sanitiser, deliberately. There is no descriptor to defer to,
                # so name-matching is the only protection available, and the export already warns
                # that nothing was declared.
                $sanitized = if ($isEnvelopeInput) {
                    @(foreach ($env in @($toSerialize)) {
                        if ($null -eq $env) { continue }
                        $clean = [ordered]@{}
                        foreach ($prop in $env.PSObject.Properties) {
                            $clean[$prop.Name] = if ($prop.Name -eq 'Data') {
                                $prop.Value
                            } else {
                                ConvertTo-GraphSanitizedObject -InputObject $prop.Value
                            }
                        }
                        $out = [pscustomobject] $clean
                        $out.PSObject.TypeNames.Insert(0, 'GraphKit.OperationResult')
                        $out
                    })
                } else {
                    ConvertTo-GraphSanitizedObject -InputObject $toSerialize
                }
                $json = if (@($sanitized).Count -eq 0) { '[]' } else { ($sanitized | ConvertTo-Json -Depth 20) }
                Set-Content -LiteralPath $filePath -Value $json -Encoding utf8
            }

            'Markdown' {
                $markdown = if ($rows.Count -eq 0) {
                    "# Graph result`n`n_No data rows._"
                } else {
                    # Rows arrive as hashtables whenever the transport parsed with -AsHashtable,
                    # and $row.PSObject.Properties on a hashtable enumerates Count/Keys/Values
                    # rather than the entries - producing a table whose columns are IsReadOnly,
                    # Keys, SyncRoot and whose values are space-joined into one cell. The Csv
                    # branch was given this guard after the same bug; Markdown never was. It bites
                    # exactly when NO declaration exists, because redaction otherwise converts
                    # rows to PSCustomObjects first - so it hits the majority of operations.
                    #
                    # Columns are unioned across ALL rows, not taken from $rows[0]: heterogeneous
                    # rows silently dropped columns that the first row happened to lack.
                    function Get-RowEntry {
                        param($R, [string] $Name)
                        if ($R -is [System.Collections.IDictionary]) { return $R[$Name] }
                        $prop = $R.PSObject.Properties[$Name]
                        if ($prop) { return $prop.Value }
                        return $null
                    }
                    $columns = [System.Collections.Generic.List[string]]::new()
                    foreach ($r in $rows) {
                        $names = if ($r -is [System.Collections.IDictionary]) { @($r.Keys) } else { @($r.PSObject.Properties.Name) }
                        foreach ($n in $names) { if (-not $columns.Contains([string] $n)) { $columns.Add([string] $n) } }
                    }
                    $columns = @($columns)
                    $header = '| ' + ($columns -join ' | ') + ' |'
                    $separator = '| ' + (($columns | ForEach-Object { '---' }) -join ' | ') + ' |'
                    $bodyLines = foreach ($row in $rows) {
                        $cells = foreach ($column in $columns) {
                            $value = Get-RowEntry -R $row -Name $column
                            if ($null -eq $value) { '' } else { "$value".Replace('|', '\|').Replace("`r", ' ').Replace("`n", ' ') }
                        }
                        '| ' + ($cells -join ' | ') + ' |'
                    }
                    (@($header, $separator) + @($bodyLines)) -join "`n"
                }
                Set-Content -LiteralPath $filePath -Value $markdown -Encoding utf8
            }
        }

        Write-Verbose "Exported $($rows.Count) row(s) as $As to '$filePath'."
        return
    }

    # --- Vault evidence ----------------------------------------------------
    if ([string]::IsNullOrWhiteSpace($ProfileId)) {
        throw '-As VaultEvidence requires -ProfileId: it is the only value used to build report and evidence paths.'
    }

    if (-not (Test-GraphProfileId -ProfileId $ProfileId)) {
        throw "ProfileId '$ProfileId' is not a valid canonical identifier (expected ^[a-z0-9][a-z0-9-]{0,63}$); display names are never path identifiers."
    }

    $reportRoot = if ([string]::IsNullOrWhiteSpace($ReportRoot)) {
        (Join-Path $HOME 'repo/report-exports')
    } else {
        $ReportRoot
    }

    $evidenceRoot = if ([string]::IsNullOrWhiteSpace($EvidenceRoot)) {
        (Join-Path $HOME 'Documents/Obsidian Vault/cdw-kb/evidence')
    } else {
        $EvidenceRoot
    }

    $reportRootFull = [System.IO.Path]::GetFullPath($reportRoot)
    $evidenceRootFull = [System.IO.Path]::GetFullPath($evidenceRoot)

    # Raw rows go under the report root (outside the vault). ProfileId is
    # path-safe by validation; containment is still asserted before writing.
    $rawDir = Join-Path $reportRootFull $ProfileId
    $rawPath = Join-Path $rawDir 'rows.json'

    if (-not (Test-GraphPathContainment -Root $reportRootFull -Candidate $rawPath)) {
        throw "Refusing to write raw rows outside the report root: '$rawPath' is not beneath '$reportRootFull'."
    }

    $null = New-Item -ItemType Directory -Path $rawDir -Force
    $rowsJson = if ($rows.Count -eq 0) { '[]' } else { ($rows.ToArray() | ConvertTo-Json -Depth 20) }
    Set-Content -LiteralPath $rawPath -Value $rowsJson -Encoding utf8

    $summary = New-GraphEvidenceSummary -Fields @{
        ProfileId    = $ProfileId
        Name         = $Name
        Kind         = $Kind
        GeneratedUtc = [datetime]::UtcNow
        SourcePaths  = @($rawPath)
        Counts       = @{ rows = $rows.Count }
        Notes        = @()
    }

    # The filesystem evidence write is the default implementation and always
    # runs; an injected -VaultAdapter receives the summary DTO as an additional
    # hook (capture, taxonomy, or an alternate destination).
    Write-VaultEvidence -Summary $summary -EvidenceRoot $evidenceRootFull -ReportRoot $reportRootFull

    if ($PSBoundParameters.ContainsKey('VaultAdapter') -and $null -ne $VaultAdapter) {
        & $VaultAdapter -Summary $summary -EvidenceRoot $evidenceRootFull -ReportRoot $reportRootFull
    }
}
