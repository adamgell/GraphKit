function global:Get-Task7JsonProperty {
    param(
        [Parameter(Mandatory)] [System.Text.Json.JsonElement] $Element,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Location
    )

    $propertyMatches = @($Element.EnumerateObject() | Where-Object Name -CEQ $Name)
    if ($propertyMatches.Count -ne 1) {
        throw [System.IO.InvalidDataException]::new("$Location must contain exactly one '$Name' property.")
    }
    return $propertyMatches[0].Value
}

function global:Assert-Task7NoDuplicateJsonProperties {
    param(
        [Parameter(Mandatory)] [System.Text.Json.JsonElement] $Element,
        [Parameter(Mandatory)] [string] $Location
    )

    if ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $seen.Add($property.Name)) {
                throw [System.IO.InvalidDataException]::new(
                    "$Location has duplicate JSON property '$($property.Name)'."
                )
            }
            Assert-Task7NoDuplicateJsonProperties -Element $property.Value `
                -Location "$Location.$($property.Name)"
        }
    }
    elseif ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        $index = 0
        foreach ($item in $Element.EnumerateArray()) {
            Assert-Task7NoDuplicateJsonProperties -Element $item -Location "$Location[$index]"
            $index++
        }
    }
}

function global:Assert-Task7ExactJsonFields {
    param(
        [Parameter(Mandatory)] [System.Text.Json.JsonElement] $Element,
        [Parameter(Mandatory)] [string[]] $Expected,
        [Parameter(Mandatory)] [string] $Location
    )

    if ($Element.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) {
        throw [System.IO.InvalidDataException]::new("$Location must be an object.")
    }
    $actual = @($Element.EnumerateObject() | ForEach-Object Name)
    $unknown = @($actual | Where-Object { $_ -cnotin $Expected })
    if ($unknown.Count -gt 0) {
        throw [System.IO.InvalidDataException]::new(
            "$Location has unknown property '$($unknown[0])'."
        )
    }
    $missing = @($Expected | Where-Object { $_ -cnotin $actual })
    if ($missing.Count -gt 0) {
        throw [System.IO.InvalidDataException]::new(
            "$Location is missing required property '$($missing[0])'."
        )
    }
}

function global:Assert-Task7JsonKind {
    param(
        [Parameter(Mandatory)] [System.Text.Json.JsonElement] $Element,
        [Parameter(Mandatory)] [System.Text.Json.JsonValueKind[]] $Allowed,
        [Parameter(Mandatory)] [string] $Location
    )
    if ($Element.ValueKind -notin $Allowed) {
        throw [System.IO.InvalidDataException]::new(
            "$Location has JSON kind '$($Element.ValueKind)' instead of '$($Allowed -join ' or ')'."
        )
    }
}

function global:Assert-Task7JsonArrayItems {
    param(
        [Parameter(Mandatory)] [System.Text.Json.JsonElement] $Element,
        [Parameter(Mandatory)] [System.Text.Json.JsonValueKind[]] $Allowed,
        [Parameter(Mandatory)] [string] $Location,
        [switch] $NestedStringArrays
    )
    Assert-Task7JsonKind -Element $Element -Allowed Array -Location $Location
    $index = 0
    foreach ($item in $Element.EnumerateArray()) {
        if ($NestedStringArrays) {
            Assert-Task7JsonArrayItems -Element $item -Allowed String `
                -Location "$Location[$index]"
        }
        else {
            Assert-Task7JsonKind -Element $item -Allowed $Allowed -Location "$Location[$index]"
            if ($item.ValueKind -eq [System.Text.Json.JsonValueKind]::String -and
                [string]::IsNullOrEmpty($item.GetString())) {
                throw [System.IO.InvalidDataException]::new(
                    "$Location[$index] must not be an empty string."
                )
            }
        }
        $index++
    }
}

function global:Assert-Task7StrictTimestamp {
    param(
        [Parameter(Mandatory)] [System.Text.Json.JsonElement] $Element,
        [Parameter(Mandatory)] [string] $Location
    )

    Assert-Task7JsonKind -Element $Element -Allowed String -Location $Location
    $literal = $Element.GetString()
    if ($literal -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$') {
        throw [System.IO.InvalidDataException]::new(
            "$Location must use exact yyyy-MM-ddTHH:mm:ss+00:00 timestamp syntax."
        )
    }

    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
        $literal,
        "yyyy-MM-dd'T'HH:mm:sszzz",
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None,
        [ref] $parsed
    )) {
        throw [System.IO.InvalidDataException]::new(
            "$Location is not a valid invariant timestamp."
        )
    }
}

function global:ConvertTo-Task7TimestampLiteral {
    param([Parameter(Mandatory)] [DateTimeOffset] $Value)
    return $Value.ToString(
        "yyyy-MM-dd'T'HH:mm:sszzz",
        [Globalization.CultureInfo]::InvariantCulture
    )
}

function global:ConvertFrom-Task7TimestampLiteral {
    param([Parameter(Mandatory)] [string] $Value)
    return [DateTimeOffset]::ParseExact(
        $Value,
        "yyyy-MM-dd'T'HH:mm:sszzz",
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None
    )
}

function global:ConvertFrom-Task7JsonElement {
    param([Parameter(Mandatory)] [System.Text.Json.JsonElement] $Element)

    switch ($Element.ValueKind) {
        Object {
            $value = [ordered] @{}
            foreach ($property in $Element.EnumerateObject()) {
                $value[$property.Name] = ConvertFrom-Task7JsonElement -Element $property.Value
            }
            return $value
        }
        Array {
            $items = [Collections.Generic.List[object]]::new()
            foreach ($item in $Element.EnumerateArray()) {
                $items.Add((ConvertFrom-Task7JsonElement -Element $item))
            }
            return ,$items.ToArray()
        }
        String { return [string] $Element.GetString() }
        Number {
            $integer = 0L
            if ($Element.TryGetInt64([ref] $integer)) { return $integer }
            return $Element.GetDecimal()
        }
        True { return $true }
        False { return $false }
        Null { return $null }
        default {
            throw [System.IO.InvalidDataException]::new(
                "Unsupported JSON value kind '$($Element.ValueKind)'."
            )
        }
    }
}

function global:Read-Task7ParityMatrixJson {
    param(
        [Parameter(Mandatory)] [string] $Json,
        [string] $Sha256 = ''
    )

    $requiredRows = [ordered] @{
        'construction-certificate' = @('construction', 'Certificate', 'construction-only', 'construction-only')
        'construction-client-secret' = @('construction', 'ClientSecret', 'construction-only', 'construction-only')
        'construction-managed-identity' = @('construction', 'ManagedIdentity', 'construction-only', 'construction-only')
        'construction-bearer-token' = @('construction', 'BearerToken', 'construction-only', 'construction-only')
        'ordinary-cache-hit' = @('cache-hit', 'Certificate', 'direct-source', 'direct-source')
        'expired-result-refresh' = @('expiry-refresh', 'ClientSecret', 'direct-source', 'direct-source')
        'ordinary-forced-ordinary' = @('force-partition', 'ManagedIdentity', 'direct-source', 'direct-source')
        'acquisition-failure-fanout-retry' = @('failure-fanout-retry', 'Certificate', 'compiled-internal-source-flight', 'legacy-production-outer-keyed-flight')
        'caller-cancellation-no-cache' = @('caller-cancellation', 'ClientSecret', 'direct-source', 'direct-source')
        'fixed-bearer-cache-force-refusal' = @('fixed-bearer', 'BearerToken', 'direct-source', 'direct-source')
        'fingerprint-certificate' = @('fingerprint', 'Certificate', 'direct-source', 'direct-source')
        'fingerprint-client-secret' = @('fingerprint', 'ClientSecret', 'direct-source', 'direct-source')
        'fingerprint-managed-identity' = @('fingerprint', 'ManagedIdentity', 'direct-source', 'direct-source')
        'fingerprint-bearer-token' = @('fingerprint', 'BearerToken', 'direct-source', 'direct-source')
        'adoption-generation-mismatch' = @('adoption-mismatch', 'Certificate', 'direct-source', 'direct-source')
        'adoption-valid' = @('adoption-valid', 'ManagedIdentity', 'direct-source', 'direct-source')
    }
    $rowFields = @(
        'id', 'runners', 'scenario', 'authMode', 'callLayerByRunner', 'input',
        'expectedByRunner'
    )
    $inputFields = @(
        'tokens', 'expiresOnUtc', 'forceFlags', 'cancelCaller', 'fingerprintInput',
        'adoptToken', 'adoptGeneration', 'adoptReceivedOnUtc', 'adoptExpiresOnUtc',
        'adoptTenantProof'
    )
    $expectedFields = @(
        'canRefresh', 'authMode', 'audience', 'clientId', 'credentialGeneration',
        'sourceExpiresOnUtc', 'sourceVerifiedTenantId', 'tokenSequence', 'expiriesOnUtc',
        'tokenTypes', 'orderedScopes', 'tenantProofs', 'fingerprints', 'generations',
        'receivedTimeRule', 'applicationConstructionCount', 'providerAcquisitionCount',
        'forceFlags', 'referenceIdentity', 'failureKind', 'cacheState',
        'finalFlightRegistryCount'
    )
    $hint = if ($Json -cmatch '"schemaVersion"\s*:\s*2') {
        'unsupported-schema-version'
    }
    elseif ($Json -cmatch '"rowCount"\s*:\s*15') {
        'incorrect-row-count'
    }
    elseif ($Json -cmatch 'replacement-row-id') {
        'missing-required-row-id'
    }
    elseif ($Json -cmatch '"unexpected"') {
        'unknown-property'
    }
    elseif ($Json -cmatch '"schemaVersion"\s*:\s*1\s*,\s*"schemaVersion"') {
        'duplicate-json-property'
    }
    else {
        'malformed-matrix'
    }

    try {
        $document = [System.Text.Json.JsonDocument]::Parse($Json)
        try {
            $root = $document.RootElement
            Assert-Task7NoDuplicateJsonProperties -Element $root -Location root
            Assert-Task7ExactJsonFields -Element $root `
                -Expected @('schemaVersion', 'rowCount', 'rows') -Location root
            $schema = Get-Task7JsonProperty -Element $root -Name schemaVersion -Location root
            $rowCount = Get-Task7JsonProperty -Element $root -Name rowCount -Location root
            Assert-Task7JsonKind -Element $schema -Allowed Number -Location root.schemaVersion
            Assert-Task7JsonKind -Element $rowCount -Allowed Number -Location root.rowCount
            if ($schema.GetInt32() -ne 1) {
                throw [System.IO.InvalidDataException]::new('schemaVersion must equal 1.')
            }
            if ($rowCount.GetInt32() -ne 16) {
                throw [System.IO.InvalidDataException]::new('rowCount must equal 16.')
            }
            $rowsElement = Get-Task7JsonProperty -Element $root -Name rows -Location root
            Assert-Task7JsonKind -Element $rowsElement -Allowed Array -Location root.rows
            if ($rowsElement.GetArrayLength() -ne 16) {
                throw [System.IO.InvalidDataException]::new('rows must contain exactly 16 items.')
            }

            $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            foreach ($row in $rowsElement.EnumerateArray()) {
                Assert-Task7NoDuplicateJsonProperties -Element $row -Location row
                Assert-Task7ExactJsonFields -Element $row -Expected $rowFields -Location row
                $idElement = Get-Task7JsonProperty -Element $row -Name id -Location row
                Assert-Task7JsonKind -Element $idElement -Allowed String -Location row.id
                $id = $idElement.GetString()
                if (-not $seen.Add($id)) {
                    throw [System.IO.InvalidDataException]::new("duplicate row id '$id'.")
                }
                if (-not $requiredRows.Contains($id)) {
                    throw [System.IO.InvalidDataException]::new("unknown row id '$id'.")
                }

                $runners = Get-Task7JsonProperty -Element $row -Name runners -Location "row '$id'"
                Assert-Task7JsonArrayItems -Element $runners -Allowed String `
                    -Location "row '$id'.runners"
                $runnerValues = @($runners.EnumerateArray() | ForEach-Object { $_.GetString() })
                if ($runnerValues.Count -ne 2 -or
                    $runnerValues[0] -cne 'xunit-compiled' -or
                    $runnerValues[1] -cne 'pester-legacy') {
                    throw [System.IO.InvalidDataException]::new(
                        "row '$id' has an invalid runner set or order."
                    )
                }
                $scenario = Get-Task7JsonProperty -Element $row -Name scenario -Location "row '$id'"
                $mode = Get-Task7JsonProperty -Element $row -Name authMode -Location "row '$id'"
                Assert-Task7JsonKind -Element $scenario -Allowed String -Location "row '$id'.scenario"
                Assert-Task7JsonKind -Element $mode -Allowed String -Location "row '$id'.authMode"
                if ($scenario.GetString() -cne $requiredRows[$id][0] -or
                    $mode.GetString() -cne $requiredRows[$id][1]) {
                    throw [System.IO.InvalidDataException]::new(
                        "row '$id' has an invalid scenario or authentication mode."
                    )
                }

                $layers = Get-Task7JsonProperty -Element $row -Name callLayerByRunner `
                    -Location "row '$id'"
                Assert-Task7NoDuplicateJsonProperties -Element $layers `
                    -Location "row '$id'.callLayerByRunner"
                Assert-Task7ExactJsonFields -Element $layers `
                    -Expected @('xunit-compiled', 'pester-legacy') `
                    -Location "row '$id'.callLayerByRunner"
                $xunitLayer = Get-Task7JsonProperty -Element $layers -Name xunit-compiled `
                    -Location "row '$id'.callLayerByRunner"
                $pesterLayer = Get-Task7JsonProperty -Element $layers -Name pester-legacy `
                    -Location "row '$id'.callLayerByRunner"
                Assert-Task7JsonKind -Element $xunitLayer -Allowed String `
                    -Location "row '$id'.callLayerByRunner.xunit-compiled"
                Assert-Task7JsonKind -Element $pesterLayer -Allowed String `
                    -Location "row '$id'.callLayerByRunner.pester-legacy"
                if ($xunitLayer.GetString() -cne $requiredRows[$id][2] -or
                    $pesterLayer.GetString() -cne $requiredRows[$id][3]) {
                    throw [System.IO.InvalidDataException]::new(
                        "row '$id' has an invalid runner call layer."
                    )
                }

                $inputElement = Get-Task7JsonProperty -Element $row -Name input -Location "row '$id'"
                Assert-Task7NoDuplicateJsonProperties -Element $inputElement -Location "row '$id'.input"
                Assert-Task7ExactJsonFields -Element $inputElement -Expected $inputFields `
                    -Location "row '$id'.input"
                foreach ($name in @('tokens', 'expiresOnUtc')) {
                    $value = Get-Task7JsonProperty -Element $inputElement -Name $name -Location "row '$id'.input"
                    Assert-Task7JsonArrayItems -Element $value -Allowed String `
                        -Location "row '$id'.input.$name"
                    if ($name -ceq 'expiresOnUtc') {
                        $dateIndex = 0
                        foreach ($timestamp in $value.EnumerateArray()) {
                            Assert-Task7StrictTimestamp -Element $timestamp `
                                -Location "row '$id'.input.$name[$dateIndex]"
                            $dateIndex++
                        }
                    }
                }
                $inputFlags = Get-Task7JsonProperty -Element $inputElement -Name forceFlags `
                    -Location "row '$id'.input"
                Assert-Task7JsonArrayItems -Element $inputFlags -Allowed @('True', 'False') `
                    -Location "row '$id'.input.forceFlags"
                $cancel = Get-Task7JsonProperty -Element $inputElement -Name cancelCaller `
                    -Location "row '$id'.input"
                Assert-Task7JsonKind -Element $cancel -Allowed @('True', 'False') `
                    -Location "row '$id'.input.cancelCaller"
                foreach ($name in @(
                    'fingerprintInput', 'adoptToken', 'adoptGeneration',
                    'adoptReceivedOnUtc', 'adoptExpiresOnUtc', 'adoptTenantProof'
                )) {
                    $value = Get-Task7JsonProperty -Element $inputElement -Name $name `
                        -Location "row '$id'.input"
                    Assert-Task7JsonKind -Element $value -Allowed @('String', 'Null') `
                        -Location "row '$id'.input.$name"
                }
                foreach ($name in @('adoptReceivedOnUtc', 'adoptExpiresOnUtc')) {
                    $value = Get-Task7JsonProperty -Element $inputElement -Name $name `
                        -Location "row '$id'.input"
                    if ($value.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                        Assert-Task7StrictTimestamp -Element $value `
                            -Location "row '$id'.input.$name"
                    }
                }

                $expectedByRunner = Get-Task7JsonProperty -Element $row `
                    -Name expectedByRunner -Location "row '$id'"
                Assert-Task7NoDuplicateJsonProperties -Element $expectedByRunner `
                    -Location "row '$id'.expectedByRunner"
                Assert-Task7ExactJsonFields -Element $expectedByRunner `
                    -Expected @('xunit-compiled', 'pester-legacy') `
                    -Location "row '$id'.expectedByRunner"
                foreach ($runner in @('xunit-compiled', 'pester-legacy')) {
                    $expected = Get-Task7JsonProperty -Element $expectedByRunner -Name $runner `
                        -Location "row '$id'.expectedByRunner"
                    $location = "row '$id'.expectedByRunner.$runner"
                    Assert-Task7NoDuplicateJsonProperties -Element $expected -Location $location
                    Assert-Task7ExactJsonFields -Element $expected -Expected $expectedFields `
                        -Location $location
                    foreach ($name in @('canRefresh')) {
                        Assert-Task7JsonKind `
                            -Element (Get-Task7JsonProperty $expected $name $location) `
                            -Allowed @('True', 'False') -Location "$location.$name"
                    }
                    foreach ($name in @(
                        'authMode', 'audience', 'credentialGeneration', 'sourceExpiresOnUtc',
                        'receivedTimeRule', 'referenceIdentity', 'cacheState'
                    )) {
                        Assert-Task7JsonKind `
                            -Element (Get-Task7JsonProperty $expected $name $location) `
                            -Allowed String -Location "$location.$name"
                    }
                    Assert-Task7StrictTimestamp `
                        -Element (Get-Task7JsonProperty $expected sourceExpiresOnUtc $location) `
                        -Location "$location.sourceExpiresOnUtc"
                    foreach ($name in @(
                        'clientId', 'sourceVerifiedTenantId', 'failureKind'
                    )) {
                        Assert-Task7JsonKind `
                            -Element (Get-Task7JsonProperty $expected $name $location) `
                            -Allowed @('String', 'Null') -Location "$location.$name"
                    }
                    foreach ($name in @(
                        'tokenSequence', 'expiriesOnUtc', 'tokenTypes', 'fingerprints',
                        'generations'
                    )) {
                        Assert-Task7JsonArrayItems `
                            -Element (Get-Task7JsonProperty $expected $name $location) `
                            -Allowed String -Location "$location.$name"
                    }
                    $expiryIndex = 0
                    foreach ($timestamp in (
                        Get-Task7JsonProperty $expected expiriesOnUtc $location
                    ).EnumerateArray()) {
                        Assert-Task7StrictTimestamp -Element $timestamp `
                            -Location "$location.expiriesOnUtc[$expiryIndex]"
                        $expiryIndex++
                    }
                    Assert-Task7JsonArrayItems `
                        -Element (Get-Task7JsonProperty $expected orderedScopes $location) `
                        -Allowed Array -NestedStringArrays -Location "$location.orderedScopes"
                    Assert-Task7JsonArrayItems `
                        -Element (Get-Task7JsonProperty $expected tenantProofs $location) `
                        -Allowed @('String', 'Null') -Location "$location.tenantProofs"
                    Assert-Task7JsonArrayItems `
                        -Element (Get-Task7JsonProperty $expected forceFlags $location) `
                        -Allowed @('True', 'False') -Location "$location.forceFlags"
                    foreach ($name in @(
                        'applicationConstructionCount', 'providerAcquisitionCount',
                        'finalFlightRegistryCount'
                    )) {
                        $number = Get-Task7JsonProperty $expected $name $location
                        Assert-Task7JsonKind -Element $number -Allowed Number `
                            -Location "$location.$name"
                        if ($number.GetInt32() -lt 0) {
                            throw [System.IO.InvalidDataException]::new(
                                "$location.$name must be a non-negative integer."
                            )
                        }
                    }
                }
            }
            $missing = @($requiredRows.Keys | Where-Object { -not $seen.Contains($_) })
            if ($missing.Count -gt 0) {
                throw [System.IO.InvalidDataException]::new(
                    "missing required row id '$($missing[0])'."
                )
            }
            $data = ConvertFrom-Task7JsonElement -Element $root
        }
        finally {
            $document.Dispose()
        }

        return [pscustomobject] @{
            SchemaVersion = [int] $data.schemaVersion
            RowCount = [int] $data.rowCount
            Rows = [object[]] @($data.rows)
            Sha256 = $Sha256
        }
    }
    catch {
        throw [System.IO.InvalidDataException]::new("$hint`: $($_.Exception.Message)", $_.Exception)
    }
}

function global:Get-Task7MalformedParityJson {
    param(
        [Parameter(Mandatory)] [string] $ValidJson,
        [Parameter(Mandatory)] [string] $MutationId
    )
    if ($MutationId -ceq 'duplicate-json-property') {
        return $ValidJson.Replace(
            '"schemaVersion": 1,',
            '"schemaVersion": 1, "schemaVersion": 1,'
        )
    }

    $document = [System.Text.Json.JsonDocument]::Parse($ValidJson)
    try {
        $data = ConvertFrom-Task7JsonElement -Element $document.RootElement
    }
    finally {
        $document.Dispose()
    }
    switch ($MutationId) {
        'unsupported-schema-version' { $data.schemaVersion = 2 }
        'incorrect-row-count' { $data.rowCount = 15 }
        'duplicate-row-id' { $data.rows[1].id = $data.rows[0].id }
        'missing-required-row-id' { $data.rows[0].id = 'replacement-row-id' }
        'unknown-property' { $data.rows[0].unexpected = $true }
        'missing-required-property' { $null = $data.rows[0].Remove('scenario') }
        'invalid-runner-call-layer' {
            $data.rows[0].callLayerByRunner.'xunit-compiled' = 'direct-source'
        }
        'missing-runner-expectation' {
            $null = $data.rows[0].expectedByRunner.Remove('pester-legacy')
        }
        default { throw "Unknown Task 7 malformed case '$MutationId'." }
    }
    return $data | ConvertTo-Json -Depth 100
}

BeforeDiscovery {
    $repoRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $fixturePath = Join-Path $repoRoot 'tests/Fixtures/GraphKitAuthParityCases.json'
    $fixtureBytes = [System.IO.File]::ReadAllBytes($fixturePath)
    $fixtureJson = [System.Text.UTF8Encoding]::new($false, $true).GetString($fixtureBytes)
    $fixtureSha = [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($fixtureBytes)
    ).ToLowerInvariant()
    $discoveredMatrix = Read-Task7ParityMatrixJson -Json $fixtureJson -Sha256 $fixtureSha
    $matrixRows = @($discoveredMatrix.Rows | ForEach-Object {
        @{ CaseId = [string] $_.id; Row = $_ }
    })
    $malformedCases = @(
        'unsupported-schema-version',
        'incorrect-row-count',
        'duplicate-row-id',
        'missing-required-row-id',
        'unknown-property',
        'missing-required-property',
        'duplicate-json-property',
        'invalid-runner-call-layer',
        'missing-runner-expectation'
    ) | ForEach-Object { @{ MutationId = $_ } }
}

BeforeAll {
    $script:ExpectedMatrixSha = 'c6953120ea3a29966acabf671a193e7ff51b38d561fb0028a2a585177dea0eb0'
    $script:RepoRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $script:FixturePath = Join-Path $script:RepoRoot 'tests/Fixtures/GraphKitAuthParityCases.json'
    $fixtureBytes = [System.IO.File]::ReadAllBytes($script:FixturePath)
    $fixtureJson = [System.Text.UTF8Encoding]::new($false, $true).GetString($fixtureBytes)
    $fixtureSha = [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($fixtureBytes)
    ).ToLowerInvariant()
    $script:Matrix = Read-Task7ParityMatrixJson -Json $fixtureJson -Sha256 $fixtureSha
    $script:FixtureJson = $fixtureJson

    $builtCandidates = @(
        Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'output/module/GraphKit') `
            -Directory | Sort-Object Name -Descending
    )
    $built = if ($builtCandidates.Count -gt 0) { $builtCandidates[0] } else { $null }
    if ($null -eq $built) {
        throw 'GraphKit is not packed. Run ./build.ps1 -Tasks pack before this file.'
    }
    $script:BuiltManifest = Join-Path $built.FullName 'GraphKit.psd1'
    Import-Module $script:BuiltManifest -Force -ErrorAction Stop

    if ($null -eq ('GraphKit.Tests.Task7LegacyHarness' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace GraphKit.Tests;

public static class Task7LegacyHarness
{
    public const string ContractMarker = "GraphKit.Task7.LegacyHarness/2";
    private static ConcurrentQueue<string> _tokens = new();
    private static ConcurrentQueue<DateTimeOffset> _expiries = new();
    private static ConcurrentQueue<bool> _forceFlags = new();
    private static int _applicationCount;
    private static int _acquisitionCount;
    private static int _outerAttempt;
    private static ConcurrentQueue<bool> _outerForceFlags = new();
    private static CountdownEvent _ready = new(1);
    private static ManualResetEventSlim _go = new(false);
    private static ManualResetEventSlim _entered = new(false);
    private static ManualResetEventSlim _release = new(false);
    private static CancellationTokenSource _cleanup = new();
    private static ConcurrentQueue<Exception> _outerFailures = new();

    public static int ApplicationCount => Volatile.Read(ref _applicationCount);
    public static int AcquisitionCount => Volatile.Read(ref _acquisitionCount);
    public static bool[] ForceFlags => _forceFlags.ToArray();
    public static Exception[] OuterFailures => _outerFailures.ToArray();

    public static void Configure(string[] tokens, DateTimeOffset[] expiries)
    {
        _tokens = new ConcurrentQueue<string>(tokens);
        _expiries = new ConcurrentQueue<DateTimeOffset>(expiries);
        _forceFlags = new ConcurrentQueue<bool>();
        _outerFailures = new ConcurrentQueue<Exception>();
        Interlocked.Exchange(ref _applicationCount, 0);
        Interlocked.Exchange(ref _acquisitionCount, 0);
    }

    public static Task7LegacyApplication CreateApplication()
    {
        Interlocked.Increment(ref _applicationCount);
        return new Task7LegacyApplication();
    }

    internal static Task7LegacyAuthenticationResult Acquire(
        bool forceRefresh,
        CancellationToken cancellation)
    {
        Interlocked.Increment(ref _acquisitionCount);
        _forceFlags.Enqueue(forceRefresh);
        cancellation.ThrowIfCancellationRequested();
        if (!_tokens.TryDequeue(out string token) || !_expiries.TryDequeue(out DateTimeOffset expiry))
        {
            throw new InvalidOperationException("No Task 7 legacy parity result remains.");
        }
        return new Task7LegacyAuthenticationResult { AccessToken = token, ExpiresOn = expiry };
    }

    public static void ConfigureOuter(
        int participants,
        string[] tokens,
        DateTimeOffset[] expiries,
        bool[] forceFlags)
    {
        CancelOuter();
        _ready.Dispose();
        _go.Dispose();
        _entered.Dispose();
        _release.Dispose();
        _cleanup.Dispose();
        _ready = new CountdownEvent(participants);
        _go = new ManualResetEventSlim(false);
        _entered = new ManualResetEventSlim(false);
        _release = new ManualResetEventSlim(false);
        _cleanup = new CancellationTokenSource();
        _tokens = new ConcurrentQueue<string>(tokens);
        _expiries = new ConcurrentQueue<DateTimeOffset>(expiries);
        _outerForceFlags = new ConcurrentQueue<bool>(forceFlags);
        _forceFlags = new ConcurrentQueue<bool>();
        _outerFailures = new ConcurrentQueue<Exception>();
        Interlocked.Exchange(ref _applicationCount, 0);
        Interlocked.Exchange(ref _acquisitionCount, 0);
        Interlocked.Exchange(ref _outerAttempt, 0);
    }

    public static bool WaitReady(int milliseconds) => _ready.Wait(milliseconds);
    public static void Go() => _go.Set();
    public static bool WaitEntered(int milliseconds) => _entered.Wait(milliseconds);
    public static void ReleaseOuter() => _release.Set();

    public static void ParticipantReadyAndWait()
    {
        _ready.Signal();
        _go.Wait(_cleanup.Token);
    }

    public static Task7LegacyAuthenticationResult AcquireOuter()
    {
        int attempt = Interlocked.Increment(ref _outerAttempt);
        Interlocked.Increment(ref _acquisitionCount);
        if (!_tokens.TryDequeue(out string token) ||
            !_expiries.TryDequeue(out DateTimeOffset expiry) ||
            !_outerForceFlags.TryDequeue(out bool forceRefresh))
        {
            throw new InvalidOperationException("No Task 7 outer parity input remains.");
        }
        _forceFlags.Enqueue(forceRefresh);
        if (attempt == 1)
        {
            _entered.Set();
            _release.Wait(_cleanup.Token);
            throw new InvalidOperationException("task7-outer-acquisition-failure");
        }
        return new Task7LegacyAuthenticationResult
        {
            AccessToken = token,
            ExpiresOn = expiry
        };
    }

    public static void CancelOuter()
    {
        try { _cleanup.Cancel(); } catch (ObjectDisposedException) { }
        try { _go.Set(); } catch (ObjectDisposedException) { }
        try { _release.Set(); } catch (ObjectDisposedException) { }
    }

    public static void RecordOuterFailure(Exception failure) => _outerFailures.Enqueue(failure);

    public static void ResetAndDispose()
    {
        CancelOuter();
        TryDispose(_ready);
        TryDispose(_go);
        TryDispose(_entered);
        TryDispose(_release);
        TryDispose(_cleanup);
        _tokens = new ConcurrentQueue<string>();
        _expiries = new ConcurrentQueue<DateTimeOffset>();
        _outerForceFlags = new ConcurrentQueue<bool>();
        _forceFlags = new ConcurrentQueue<bool>();
        _outerFailures = new ConcurrentQueue<Exception>();
        Interlocked.Exchange(ref _applicationCount, 0);
        Interlocked.Exchange(ref _acquisitionCount, 0);
        Interlocked.Exchange(ref _outerAttempt, 0);
    }

    private static void TryDispose(IDisposable value)
    {
        try { value.Dispose(); } catch (ObjectDisposedException) { }
    }
}

public sealed class Task7LegacyApplication
{
    public Task7LegacyBuilder AcquireTokenForClient(string[] scopes) => new();
    public Task7LegacyBuilder AcquireTokenForManagedIdentity(string scope) => new();
}

public sealed class Task7LegacyBuilder
{
    private bool _forceRefresh;

    public Task7LegacyBuilder WithForceRefresh(bool forceRefresh)
    {
        _forceRefresh = forceRefresh;
        return this;
    }

    public Task<Task7LegacyAuthenticationResult> ExecuteAsync(CancellationToken cancellation) =>
        Task.FromResult(Task7LegacyHarness.Acquire(_forceRefresh, cancellation));
}

public sealed class Task7LegacyAuthenticationResult
{
    public string AccessToken { get; set; } = string.Empty;
    public DateTimeOffset ExpiresOn { get; set; }
}
'@
    }
    $harnessType = 'GraphKit.Tests.Task7LegacyHarness' -as [type]
    if ($null -eq $harnessType -or
        [string] $harnessType.GetField('ContractMarker').GetRawConstantValue() -cne
            'GraphKit.Task7.LegacyHarness/2') {
        throw 'The process-global Task 7 legacy harness has an incompatible identity or contract.'
    }

    function New-Task7LegacySource {
        param([Parameter(Mandatory)] $Row)
        $mode = [string] $Row.authMode
        $token = if ([string] $Row.scenario -ceq 'fingerprint') {
            [string] $Row.input.fingerprintInput
        }
        elseif (@($Row.input.tokens).Count -gt 0) {
            [string] $Row.input.tokens[0]
        }
        else {
            'task7-unused-bearer'
        }
        InModuleScope GraphKit -Parameters @{ Mode = $mode; Token = $token } {
            param($Mode, $Token)
            $factory = [scriptblock]::Create(
                '[GraphKit.Tests.Task7LegacyHarness]::CreateApplication()'
            )
            switch ($Mode) {
                'Certificate' {
                    [ConfidentialClientTokenSource]::new(
                        $factory,
                        'Certificate',
                        'https://graph.microsoft.com',
                        '00000000-0000-0000-0000-000000000002',
                        'task7-generation'
                    )
                }
                'ClientSecret' {
                    [ConfidentialClientTokenSource]::new(
                        $factory,
                        'ClientSecret',
                        'https://graph.microsoft.com',
                        '00000000-0000-0000-0000-000000000002',
                        'task7-generation'
                    )
                }
                'ManagedIdentity' {
                    [ManagedIdentityTokenSource]::new(
                        $factory,
                        'https://graph.microsoft.com',
                        '00000000-0000-0000-0000-000000000003',
                        'task7-generation'
                    )
                }
                'BearerToken' {
                    [FixedBearerTokenSource]::new(
                        $Token,
                        'https://graph.microsoft.com',
                        'task7-generation'
                    )
                }
            }
        }
    }

    function New-Task7LegacyAdoptedResult {
        param([Parameter(Mandatory)] $ParityInput)
        InModuleScope GraphKit -Parameters @{ ParityInput = $ParityInput } {
            param($ParityInput)
            $result = [GraphTokenResult]::new()
            $result.AccessToken = [string] $ParityInput.adoptToken
            $result.ExpiresOnUtc = ConvertFrom-Task7TimestampLiteral `
                ([string] $ParityInput.adoptExpiresOnUtc)
            $result.ReceivedOnUtc = ConvertFrom-Task7TimestampLiteral `
                ([string] $ParityInput.adoptReceivedOnUtc)
            $result.TokenType = 'Bearer'
            $result.Scopes = [string[]] @('https://graph.microsoft.com/.default')
            $result.VerifiedTenantId = $ParityInput.adoptTenantProof
            $result.TokenFingerprint = Get-GraphFingerprint -Value ([string] $ParityInput.adoptToken)
            $result.CredentialGeneration = [string] $ParityInput.adoptGeneration
            return $result
        }
    }

    function Get-Task7LegacyFailureKind {
        param([Parameter(Mandatory)] [Exception] $Exception)
        $candidate = $Exception
        while ($null -ne $candidate) {
            if ($candidate -is [OperationCanceledException]) { return 'Canceled' }
            $candidate = $candidate.InnerException
        }
        if ($Exception.Message -match 'cannot be refreshed') { return 'RefreshRefused' }
        if ($Exception.Message -match 'credential generation') { return 'GenerationMismatch' }
        return 'AcquisitionFailure'
    }

    function Get-Task7InnermostException {
        param([Parameter(Mandatory)] [Exception] $Exception)
        $candidate = $Exception
        while ($null -ne $candidate.InnerException) {
            $candidate = $candidate.InnerException
        }
        return $candidate
    }

    function Get-Task7LegacyCacheState {
        param([Parameter(Mandatory)] $Source)
        $populated = InModuleScope GraphKit -Parameters @{ Source = $Source } {
            param($Source)
            return $null -ne $Source.GetCachedToken()
        }
        if ($populated) { return 'Populated' }
        return 'Empty'
    }

    function Get-Task7OuterFlightCount {
        InModuleScope GraphKit {
            return [GraphTokenFlightRegistry]::Flights.Count
        }
    }

    function Get-Task7OuterWaiterCount {
        param([Parameter(Mandatory)] [string] $Key)
        InModuleScope GraphKit -Parameters @{ Key = $Key } {
            param($Key)
            $flight = [GraphTokenFlight] $null
            if (-not [GraphTokenFlightRegistry]::Flights.TryGetValue($Key, [ref] $flight)) {
                return -1
            }
            return [int] (Get-GraphTokenFlightWaiterCount -Flight $flight)
        }
    }

    function Invoke-Task7LegacyOuterFailure {
        param(
            [Parameter(Mandatory)] $Source,
            [Parameter(Mandatory)] $Row
        )
        $key = 'task7-parity-' + [guid]::NewGuid().ToString('N')
        $workers = [Collections.Generic.List[object]]::new()
        $outerTokens = [string[]] @($Row.input.tokens)
        $outerExpiries = [DateTimeOffset[]] @($Row.input.expiresOnUtc | ForEach-Object {
            ConvertFrom-Task7TimestampLiteral ([string] $_)
        })
        $outerForceFlags = [bool[]] @($Row.input.forceFlags)
        [GraphKit.Tests.Task7LegacyHarness]::ConfigureOuter(
            4,
            $outerTokens,
            $outerExpiries,
            $outerForceFlags
        )
        $waitersObserved = $false
        try {
            # Start-ThreadJob shares a process-global throttle. Prepare dedicated
            # runspaces synchronously so this test measures token-flight fan-out,
            # not ambient job-scheduler capacity.
            1..4 | ForEach-Object {
                $runspace = [runspacefactory]::CreateRunspace()
                $worker = [pscustomobject] @{
                    PowerShell = $null
                    Runspace = $runspace
                    Async = $null
                    Received = $false
                }
                $workers.Add($worker)
                $runspace.ThreadOptions =
                    [System.Management.Automation.Runspaces.PSThreadOptions]::UseNewThread
                $runspace.Open()

                $initializer = [powershell]::Create()
                try {
                    $initializer.Runspace = $runspace
                    $null = $initializer.AddCommand('Import-Module').
                        AddParameter('Name', $script:BuiltManifest).
                        AddParameter('Force', $true).
                        AddParameter('ErrorAction', 'Stop').Invoke()
                    if ($initializer.HadErrors) {
                        $messages = @($initializer.Streams.Error | ForEach-Object {
                            $_.Exception.Message
                        }) -join '; '
                        throw "Dedicated Task 7 worker failed to import GraphKit: $messages"
                    }
                }
                finally {
                    $initializer.Dispose()
                }

                $pipeline = [powershell]::Create()
                $worker.PowerShell = $pipeline
                $pipeline.Runspace = $runspace
                $null = $pipeline.AddScript({
                    param($Key)
                    $module = Get-Module -Name GraphKit
                    $state = $null
                    $outcome = $null
                    try {
                        $state = & $module { $script:GraphKitModuleLifecycle }
                        [GraphKit.Tests.Task7LegacyHarness]::ParticipantReadyAndWait()
                        $result = & $module {
                            param($Key)
                            Invoke-GraphTokenSingleFlight -Key $Key -AcquireScript {
                                $auth = [GraphKit.Tests.Task7LegacyHarness]::AcquireOuter()
                                $token = [GraphTokenResult]::new()
                                $token.AccessToken = $auth.AccessToken
                                $token.ExpiresOnUtc = $auth.ExpiresOn
                                $token.ReceivedOnUtc = [DateTimeOffset]::UtcNow
                                $token.TokenType = 'Bearer'
                                $token.Scopes = [string[]] @('https://graph.microsoft.com/.default')
                                $token.VerifiedTenantId = $null
                                $token.TokenFingerprint = Get-GraphFingerprint -Value $auth.AccessToken
                                $token.CredentialGeneration = 'task7-generation'
                                return $token
                            }
                        } $Key
                        $outcome = [pscustomobject] @{ Failed = $false; Result = $result }
                    }
                    catch {
                        [GraphKit.Tests.Task7LegacyHarness]::RecordOuterFailure($_.Exception)
                        $outcome = [pscustomobject] @{
                            Failed = $true
                            Message = $_.Exception.Message
                            ErrorText = ($_ | Out-String)
                        }
                    }
                    finally {
                        if ($null -ne $module) {
                            Remove-Module $module -Force -ErrorAction SilentlyContinue
                        }
                        $cleaned = $null -ne $state -and $state.WaitForCleanup(5000)
                        $module = $null
                        $state = $null
                    }
                    $outcome | Add-Member NoteProperty ChildCleanup $cleaned
                    return $outcome
                }).AddArgument($key)
            }

            foreach ($worker in $workers) {
                $worker.Async = $worker.PowerShell.BeginInvoke()
            }
            [GraphKit.Tests.Task7LegacyHarness]::WaitReady(5000) | Should -BeTrue
            [GraphKit.Tests.Task7LegacyHarness]::Go()
            [GraphKit.Tests.Task7LegacyHarness]::WaitEntered(5000) | Should -BeTrue
            $waitersObserved = [Threading.SpinWait]::SpinUntil(
                [Func[bool]] { (Get-Task7OuterWaiterCount -Key $key) -eq 3 },
                5000
            )
            [GraphKit.Tests.Task7LegacyHarness]::ReleaseOuter()
            $outcomes = @(
                foreach ($worker in $workers) {
                    $worker.Async.AsyncWaitHandle.WaitOne(10000) |
                        Should -BeTrue -Because 'each dedicated Task 7 worker must complete'
                    $worker.Received = $true
                    $worker.PowerShell.EndInvoke($worker.Async)
                }
            )
            $outcomes.Count | Should -Be 4
            @($outcomes | Where-Object Failed).Count | Should -Be 4
            $actualFailures = @([GraphKit.Tests.Task7LegacyHarness]::OuterFailures)
            $actualFailures.Count | Should -Be 4
            $normalizedKinds = @($actualFailures | ForEach-Object {
                $rootFailure = Get-Task7InnermostException -Exception $_
                $rootFailure.GetType().FullName | Should -BeExactly `
                    'System.InvalidOperationException'
                $rootFailure.Message | Should -BeExactly 'task7-outer-acquisition-failure'
                Get-Task7LegacyFailureKind -Exception $rootFailure
            })
            @($normalizedKinds | Select-Object -Unique) | Should -Be @('AcquisitionFailure')
            @($outcomes | Where-Object { -not $_.ChildCleanup }).Count | Should -Be 0

            $recovered = InModuleScope GraphKit -Parameters @{ Key = $key } {
                param($Key)
                Invoke-GraphTokenSingleFlight -Key $Key -AcquireScript {
                    $auth = [GraphKit.Tests.Task7LegacyHarness]::AcquireOuter()
                    $token = [GraphTokenResult]::new()
                    $token.AccessToken = $auth.AccessToken
                    $token.ExpiresOnUtc = $auth.ExpiresOn
                    $token.ReceivedOnUtc = [DateTimeOffset]::UtcNow
                    $token.TokenType = 'Bearer'
                    $token.Scopes = [string[]] @('https://graph.microsoft.com/.default')
                    $token.VerifiedTenantId = $null
                    $token.TokenFingerprint = Get-GraphFingerprint -Value $auth.AccessToken
                    $token.CredentialGeneration = 'task7-generation'
                    return $token
                }
            }
            $Source.AdoptSharedResult($recovered, [bool] $Row.input.forceFlags[1])
            return [pscustomobject] @{
                Result = $recovered
                FailureKind = [string] $normalizedKinds[0]
                WaitersObserved = $waitersObserved
            }
        }
        finally {
            [GraphKit.Tests.Task7LegacyHarness]::CancelOuter()
            foreach ($worker in $workers) {
                if ($null -ne $worker.Async -and -not $worker.Received) {
                    if ($worker.Async.AsyncWaitHandle.WaitOne(10000)) {
                        try { $null = $worker.PowerShell.EndInvoke($worker.Async) } catch { }
                    }
                    else {
                        try { $worker.PowerShell.Stop() } catch { }
                    }
                }
                if ($null -ne $worker.PowerShell) { $worker.PowerShell.Dispose() }
                if ($null -ne $worker.Runspace) {
                    try { $worker.Runspace.Close() } catch { }
                    $worker.Runspace.Dispose()
                }
            }
        }
    }

    function Assert-Task7DeclarativeInputContract {
        param([Parameter(Mandatory)] $Row)

        $rowId = [string] $Row.id
        [bool] $Row.input.cancelCaller |
            Should -Be ($rowId -ceq 'caller-cancellation-no-cache')

        $fingerprintScenario = [string] $Row.scenario -ceq 'fingerprint'
        if ($fingerprintScenario) {
            [string] $Row.input.fingerprintInput | Should -Not -BeNullOrEmpty
            [string[]] @($Row.input.tokens) |
                Should -Be @([string] $Row.input.fingerprintInput)
        }
        else {
            ($null -eq $Row.input.fingerprintInput) | Should -BeTrue
        }

        $expectedForceFlags = switch -Exact ($rowId) {
            { $_ -in @(
                'construction-certificate', 'construction-client-secret',
                'construction-managed-identity', 'construction-bearer-token'
            ) } { [bool[]] @(); break }
            { $_ -in @(
                'ordinary-cache-hit', 'expired-result-refresh',
                'acquisition-failure-fanout-retry'
            ) } { [bool[]] @($false, $false); break }
            'ordinary-forced-ordinary' { [bool[]] @($false, $true, $false); break }
            { $_ -in @(
                'caller-cancellation-no-cache', 'fingerprint-certificate',
                'fingerprint-client-secret', 'fingerprint-managed-identity',
                'fingerprint-bearer-token', 'adoption-generation-mismatch',
                'adoption-valid'
            ) } { [bool[]] @($false); break }
            'fixed-bearer-cache-force-refusal' {
                [bool[]] @($false, $false, $true)
                break
            }
            default { throw "Unhandled Task 7 input contract row '$rowId'." }
        }
        [bool[]] @($Row.input.forceFlags) | Should -Be $expectedForceFlags

        if ($rowId -ceq 'acquisition-failure-fanout-retry') {
            [string[]] @($Row.input.tokens) |
                Should -Be @('task7-failure', 'task7-recovered')
            [string[]] @($Row.input.expiresOnUtc) | Should -Be @(
                '2099-04-01T00:00:00+00:00',
                '2099-04-01T00:00:00+00:00'
            )
        }
    }

    function Invoke-Task7LegacyRow {
        param([Parameter(Mandatory)] $Row)
        Assert-Task7DeclarativeInputContract -Row $Row
        [string[]] $tokens = @($Row.input.tokens)
        if ([string] $Row.scenario -ceq 'fingerprint') {
            $tokens = [string[]] @([string] $Row.input.fingerprintInput)
        }
        $expiries = [DateTimeOffset[]] @($Row.input.expiresOnUtc | ForEach-Object {
            ConvertFrom-Task7TimestampLiteral ([string] $_)
        })
        [GraphKit.Tests.Task7LegacyHarness]::Configure($tokens, $expiries)
        $source = New-Task7LegacySource -Row $Row
        $results = [Collections.Generic.List[object]]::new()
        $adopted = $null
        $failureKind = $null
        $waitersObserved = $null

        $rowId = [string] $Row.id
        if ($rowId -in @(
            'construction-certificate', 'construction-client-secret',
            'construction-managed-identity', 'construction-bearer-token'
        )) {
            # Construction is deliberately acquisition-free.
        }
        elseif ($rowId -in @(
            'ordinary-cache-hit', 'expired-result-refresh',
            'ordinary-forced-ordinary', 'fingerprint-certificate',
            'fingerprint-client-secret', 'fingerprint-managed-identity',
            'fingerprint-bearer-token'
        )) {
            foreach ($force in @($Row.input.forceFlags)) {
                $results.Add($source.Acquire(
                    [bool] $force,
                    [Threading.CancellationToken]::None
                ))
            }
        }
        elseif ($rowId -ceq 'acquisition-failure-fanout-retry') {
            $outer = Invoke-Task7LegacyOuterFailure -Source $source -Row $Row
            $results.Add($outer.Result)
            $failureKind = $outer.FailureKind
            $waitersObserved = $outer.WaitersObserved
        }
        elseif ($rowId -ceq 'caller-cancellation-no-cache') {
                $cancellation = [Threading.CancellationTokenSource]::new()
                try {
                    if ([bool] $Row.input.cancelCaller) {
                        $cancellation.Cancel()
                    }
                    try {
                        $null = $source.Acquire(
                            [bool] $Row.input.forceFlags[0],
                            $cancellation.Token
                        )
                        throw 'Task 7 expected legacy caller cancellation.'
                    }
                    catch {
                        $failureKind = Get-Task7LegacyFailureKind -Exception $_.Exception
                    }
                }
                finally { $cancellation.Dispose() }
        }
        elseif ($rowId -ceq 'fixed-bearer-cache-force-refusal') {
            $results.Add($source.Acquire(
                [bool] $Row.input.forceFlags[0],
                [Threading.CancellationToken]::None
            ))
            $results.Add($source.Acquire(
                [bool] $Row.input.forceFlags[1],
                [Threading.CancellationToken]::None
            ))
            try {
                $null = $source.Acquire(
                    [bool] $Row.input.forceFlags[2],
                    [Threading.CancellationToken]::None
                )
                throw 'Task 7 expected fixed-bearer force refusal.'
            }
            catch {
                $failureKind = Get-Task7LegacyFailureKind -Exception $_.Exception
            }
        }
        elseif ($rowId -ceq 'adoption-generation-mismatch') {
            $adopted = New-Task7LegacyAdoptedResult -ParityInput $Row.input
            try {
                $source.AdoptSharedResult($adopted, [bool] $Row.input.forceFlags[0])
                throw 'Task 7 expected generation mismatch.'
            }
            catch {
                $failureKind = Get-Task7LegacyFailureKind -Exception $_.Exception
            }
        }
        elseif ($rowId -ceq 'adoption-valid') {
            $adopted = New-Task7LegacyAdoptedResult -ParityInput $Row.input
            $source.AdoptSharedResult($adopted, [bool] $Row.input.forceFlags[0])
            $results.Add($source.Acquire(
                [bool] $Row.input.forceFlags[0],
                [Threading.CancellationToken]::None
            ))
        }
        else {
            throw "Unhandled Task 7 legacy parity row '$rowId'."
        }

        return [pscustomobject] @{
            Source = $source
            Results = [object[]] $results.ToArray()
            Adopted = $adopted
            FailureKind = $failureKind
            ApplicationConstructionCount = [GraphKit.Tests.Task7LegacyHarness]::ApplicationCount
            ProviderAcquisitionCount = [GraphKit.Tests.Task7LegacyHarness]::AcquisitionCount
            ForceFlags = [bool[]] [GraphKit.Tests.Task7LegacyHarness]::ForceFlags
            CacheState = Get-Task7LegacyCacheState -Source $source
            FinalFlightRegistryCount = Get-Task7OuterFlightCount
            WaitersObserved = $waitersObserved
        }
    }

    function ConvertTo-Task7Signature {
        param([AllowNull()] $Value)
        return ConvertTo-Json -InputObject @($Value) -Compress -Depth 20
    }
}

AfterAll {
    if ($null -ne ('GraphKit.Tests.Task7LegacyHarness' -as [type])) {
        [GraphKit.Tests.Task7LegacyHarness]::ResetAndDispose()
    }
    Remove-Module GraphKit -Force -ErrorAction SilentlyContinue
    foreach ($name in @(
        'Get-Task7JsonProperty',
        'Assert-Task7NoDuplicateJsonProperties',
        'Assert-Task7ExactJsonFields',
        'Assert-Task7JsonKind',
        'Assert-Task7JsonArrayItems',
        'Assert-Task7StrictTimestamp',
        'ConvertTo-Task7TimestampLiteral',
        'ConvertFrom-Task7TimestampLiteral',
        'ConvertFrom-Task7JsonElement',
        'Read-Task7ParityMatrixJson',
        'Get-Task7MalformedParityJson'
    )) {
        Remove-Item -LiteralPath "Function:\global:$name" -Force -ErrorAction SilentlyContinue
    }
}

Describe 'GraphKit.Auth strict deterministic parity matrix' -Tag Unit {
    It 'runs legacy semantic row <CaseId> exactly once' -ForEach $matrixRows {
        $script:Matrix.Sha256 | Should -BeExactly $script:ExpectedMatrixSha
        $script:Matrix.RowCount | Should -Be 16
        $runtimeIds = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal
        )
        foreach ($runtimeRow in $script:Matrix.Rows) {
            $runtimeIds.Add([string] $runtimeRow['id']) | Should -BeTrue
        }
        $runtimeIds.Count | Should -Be 16
        @($Row.runners) | Should -Be @('xunit-compiled', 'pester-legacy')
        [string] $Row.callLayerByRunner.'pester-legacy' | Should -Not -BeNullOrEmpty

        $expected = $Row.expectedByRunner.'pester-legacy'
        $actual = Invoke-Task7LegacyRow -Row $Row
        $source = $actual.Source

        $source.CanRefresh | Should -Be ([bool] $expected.canRefresh)
        [string] $source.AuthMode | Should -BeExactly ([string] $expected.authMode)
        [string] $source.Audience | Should -BeExactly ([string] $expected.audience)
        if ($null -eq $expected.clientId) {
            $source.ClientId | Should -BeNullOrEmpty
        }
        else {
            [string] $source.ClientId | Should -BeExactly ([string] $expected.clientId)
        }
        [string] $source.CredentialGeneration | Should -BeExactly `
            ([string] $expected.credentialGeneration)
        ConvertTo-Task7TimestampLiteral ([DateTimeOffset] $source.ExpiresOn) |
            Should -BeExactly ([string] $expected.sourceExpiresOnUtc)
        if ($null -eq $expected.sourceVerifiedTenantId) {
            $source.VerifiedTenantId | Should -BeNullOrEmpty
        }
        else {
            [string] $source.VerifiedTenantId | Should -BeExactly `
                ([string] $expected.sourceVerifiedTenantId)
        }

        $results = @($actual.Results)
        ConvertTo-Task7Signature @($results | ForEach-Object AccessToken) |
            Should -BeExactly (ConvertTo-Task7Signature @($expected.tokenSequence))
        ConvertTo-Task7Signature @($results | ForEach-Object {
            ConvertTo-Task7TimestampLiteral ([DateTimeOffset] $_.ExpiresOnUtc)
        }) | Should -BeExactly (ConvertTo-Task7Signature @($expected.expiriesOnUtc))
        ConvertTo-Task7Signature @($results | ForEach-Object TokenType) |
            Should -BeExactly (ConvertTo-Task7Signature @($expected.tokenTypes))
        ConvertTo-Task7Signature @($results | ForEach-Object {
            [string]::Join([char] 0x1f, [string[]] $_.Scopes)
        }) | Should -BeExactly (ConvertTo-Task7Signature @(
            $expected.orderedScopes | ForEach-Object {
                [string]::Join([char] 0x1f, [string[]] $_)
            }
        ))
        $actualTenantProofs = [Collections.Generic.List[object]]::new()
        foreach ($result in $results) {
            $proof = [string] $result.VerifiedTenantId
            $actualTenantProofs.Add($(if ([string]::IsNullOrEmpty($proof)) {
                $null
            }
            else {
                $proof
            }))
        }
        ConvertTo-Task7Signature $actualTenantProofs.ToArray() |
            Should -BeExactly (ConvertTo-Task7Signature @($expected.tenantProofs))
        ConvertTo-Task7Signature @($results | ForEach-Object TokenFingerprint) |
            Should -BeExactly (ConvertTo-Task7Signature @($expected.fingerprints))
        ConvertTo-Task7Signature @($results | ForEach-Object CredentialGeneration) |
            Should -BeExactly (ConvertTo-Task7Signature @($expected.generations))

        switch ([string] $expected.receivedTimeRule) {
            'None' { $results.Count | Should -Be 0 }
            'WallClock' {
                $previous = [DateTimeOffset]::MinValue
                foreach ($result in $results) {
                    $received = [DateTimeOffset] $result.ReceivedOnUtc
                    $received | Should -BeGreaterThan ([DateTimeOffset]::MinValue)
                    $received | Should -BeGreaterOrEqual $previous
                    if ([DateTimeOffset] $result.ExpiresOnUtc -gt [DateTimeOffset]::UtcNow) {
                        $received | Should -BeLessOrEqual ([DateTimeOffset] $result.ExpiresOnUtc)
                    }
                    $previous = $received
                }
            }
            'LiteralAdopted' {
                foreach ($result in $results) {
                    ConvertTo-Task7TimestampLiteral ([DateTimeOffset] $result.ReceivedOnUtc) |
                        Should -BeExactly ([string] $Row.input.adoptReceivedOnUtc)
                }
            }
            default { throw "Unexpected legacy received-time rule '$($expected.receivedTimeRule)'." }
        }

        $actual.ApplicationConstructionCount | Should -Be `
            ([int] $expected.applicationConstructionCount)
        $actual.ProviderAcquisitionCount | Should -Be `
            ([int] $expected.providerAcquisitionCount)
        ConvertTo-Task7Signature @($actual.ForceFlags) |
            Should -BeExactly (ConvertTo-Task7Signature @($expected.forceFlags))
        switch ([string] $expected.referenceIdentity) {
            'None' { $results.Count | Should -Be 0 }
            'Single' { $results.Count | Should -Be 1 }
            'AllSame' {
                foreach ($result in $results) {
                    [object]::ReferenceEquals($results[0], $result) | Should -BeTrue
                }
            }
            'AllDistinct' {
                [object]::ReferenceEquals($results[0], $results[1]) | Should -BeFalse
            }
            'SecondAndThirdSame' {
                [object]::ReferenceEquals($results[0], $results[1]) | Should -BeFalse
                [object]::ReferenceEquals($results[1], $results[2]) | Should -BeTrue
            }
            'AdoptedAndReturnedSame' {
                [object]::ReferenceEquals($actual.Adopted, $results[0]) | Should -BeTrue
            }
            default { throw "Unexpected Task 7 reference rule '$($expected.referenceIdentity)'." }
        }
        if ($null -eq $expected.failureKind) {
            $actual.FailureKind | Should -BeNullOrEmpty
        }
        else {
            [string] $actual.FailureKind | Should -BeExactly ([string] $expected.failureKind)
        }
        [string] $actual.CacheState | Should -BeExactly ([string] $expected.cacheState)
        $actual.FinalFlightRegistryCount | Should -Be ([int] $expected.finalFlightRegistryCount)
        if ($CaseId -ceq 'acquisition-failure-fanout-retry') {
            $actual.WaitersObserved | Should -BeTrue -Because `
                'outer GraphTokenFlight must expose exactly three live followers before release'
        }
    }

    It 'rejects malformed matrix case <MutationId> independently' -ForEach $malformedCases {
        $malformed = Get-Task7MalformedParityJson -ValidJson $script:FixtureJson `
            -MutationId $MutationId
        $caught = $null
        try {
            $null = Read-Task7ParityMatrixJson -Json $malformed
        }
        catch {
            $caught = $_.Exception
        }
        $caught | Should -Not -BeNullOrEmpty
        $expectedDiagnostic = switch ($MutationId) {
            'duplicate-row-id' { 'duplicate row id' }
            'missing-required-property' { 'missing required property' }
            'invalid-runner-call-layer' { 'invalid runner call layer' }
            'missing-runner-expectation' { "missing required property 'pester-legacy'" }
            default { $MutationId }
        }
        $caught.Message | Should -Match ([regex]::Escape($expectedDiagnostic))
    }
}
