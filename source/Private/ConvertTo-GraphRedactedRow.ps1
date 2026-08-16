<#
    Private: replace descriptor-declared secret-bearing properties in an export row.

    This is deliberately NOT ConvertTo-GraphSanitizedObject. That function sanitises the
    ENVELOPE - telemetry, sanitised URIs, $filter/$search query values - by matching property
    names against a broad pattern. Measured against real Graph responses, reusing it on data
    rows would redact nine DeviceCompliancePolicy settings (passwordRequired,
    passwordMinimumLength and siblings - policy configuration, not secrets) while missing
    scriptContent and Settings Catalog values entirely. That combination is worse than no
    redaction: the export carries [REDACTED] markers, reads as sanitised, and still holds the
    secrets.

    So redaction here is DECLARED, not guessed. An operation names the properties its responses
    are known to carry secrets in, exactly as it names its permissions, and only those are
    replaced. Nothing is inferred from a property's name.

    Declarations may be dotted paths. 'scriptContent' replaces a top-level value;
    'settingInstance.groupSettingCollectionValue' replaces only that nested branch and leaves
    settingDefinitionId and the rest of the row intact. Without nested support the Settings
    Catalog case would force a choice between redacting the whole settingInstance - which
    destroys everything useful about the row - and not covering it at all.

    Row SHAPE is preserved: the same top-level properties come out, so Export-Csv derives the
    same columns it would have without redaction. A row whose columns changed under redaction
    would silently alter every downstream report.
#>

function ConvertTo-GraphRedactedRow {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Row,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $SensitiveProperties
    )

    if ($null -eq $Row -or $SensitiveProperties.Count -eq 0) {
        return $Row
    }

    $marker = '[REDACTED]'

    # Group declarations by their first segment so each top-level property is handled once:
    # a bare name replaces the whole value, a dotted path recurses into it.
    $terminal = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $nested = @{}

    foreach ($declaration in $SensitiveProperties) {
        if ([string]::IsNullOrWhiteSpace($declaration)) { continue }
        $segments = $declaration.Split('.', 2)
        if ($segments.Count -eq 1) {
            $null = $terminal.Add($segments[0])
        }
        else {
            if (-not $nested.ContainsKey($segments[0])) { $nested[$segments[0]] = [System.Collections.Generic.List[string]]::new() }
            $nested[$segments[0]].Add($segments[1])
        }
    }

    # Copy rather than mutate. The caller's in-memory rows are legitimately unredacted - it is
    # the EXPORT that is the risk - and mutating them would strip values from an object the
    # caller is still using.
    $copy = [ordered]@{}

    $properties = if ($Row -is [System.Collections.IDictionary]) {
        @($Row.Keys | ForEach-Object { [pscustomobject]@{ Name = $_; Value = $Row[$_] } })
    }
    else {
        @($Row.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Value = $_.Value } })
    }

    foreach ($property in $properties) {
        if ($terminal.Contains($property.Name)) {
            $copy[$property.Name] = $marker
            continue
        }

        $nestedKey = $nested.Keys | Where-Object { $_ -eq $property.Name } | Select-Object -First 1
        if ($null -ne $nestedKey -and $null -ne $property.Value) {
            $copy[$property.Name] = ConvertTo-GraphRedactedRow -Row $property.Value -SensitiveProperties @($nested[$nestedKey])
            continue
        }

        $copy[$property.Name] = $property.Value
    }

    return [pscustomobject] $copy
}
