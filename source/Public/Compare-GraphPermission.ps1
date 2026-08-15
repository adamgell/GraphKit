function Compare-GraphPermission {
    <#
        .SYNOPSIS
            Compares two permission sets (baseline and actual) to identify missing, extra and matched entries.

        .DESCRIPTION
            Accepts a baseline (expected) permission set and an actual (observed) set, each an array of
            hashtables or objects carrying Type and Value fields, and returns a GraphKit.PermissionComparison
            record with three lists: Missing (baseline entries not observed), Extra (observed entries not in the
            baseline) and Matched (entries present in both sets). Matching compares Type and Value
            case-insensitively; the returned entries preserve the original shapes and references. The function is a
            pure comparator with no I/O and is used both for grant-vs-baseline and configured-vs-granted analysis.

        .EXAMPLE
            $baseline = @(
                @{ Type = 'Application'; Value = 'DeviceManagementManagedDevices.Read.All' },
                @{ Type = 'Application'; Value = 'DeviceManagementApps.Read.All' }
            )
            $actual = @(
                [PSCustomObject]@{ Type = 'Application'; Value = 'DeviceManagementManagedDevices.Read.All' }
            )
            Compare-GraphPermission -Baseline $baseline -Actual $actual

            Returns a comparison where the first baseline entry is Matched and the second is Missing.

        .PARAMETER Baseline
            The expected (reference) permission set: an array of hashtables or objects each carrying
            Type (string) and Value (string) fields. Entries may be shaped as operation-required-permissions
            or stand-alone permission records.

        .PARAMETER Actual
            The observed (granted or configured) permission set, same shape as Baseline. Comparison
            is one-to-one per entry: a baseline entry matched once is consumed and cannot match again.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [AllowEmptyCollection()]
        [object[]] $Baseline = @(),

        [AllowEmptyCollection()]
        [object[]] $Actual = @()
    )

    $matched = [System.Collections.Generic.List[object]]::new()
    $missing = [System.Collections.Generic.List[object]]::new()
    $actualRemaining = [System.Collections.Generic.List[object]]::new()

    foreach ($entry in $Actual) {
        [void] $actualRemaining.Add($entry)
    }

    foreach ($entry in $Baseline) {
        $foundIndex = -1

        for ($i = 0; $i -lt $actualRemaining.Count; $i++) {
            if (Test-GraphPermissionEntryMatch -A $entry -B $actualRemaining[$i]) {
                $foundIndex = $i
                break
            }
        }

        if ($foundIndex -ge 0) {
            [void] $matched.Add($entry)
            $actualRemaining.RemoveAt($foundIndex)
        } else {
            [void] $missing.Add($entry)
        }
    }

    return [PSCustomObject] @{
        PSTypeName = 'GraphKit.PermissionComparison'
        Missing    = @($missing)
        Extra      = @($actualRemaining)
        Matched    = @($matched)
    }
}
