# Operation descriptor loader and validator (phase 1).
#
# Descriptors are data-only .psd1 files loaded with Import-PowerShellDataFile,
# which executes nothing. The loader enforces the full descriptor schema from
# the design spec: SchemaVersion = 1 (newer versions are refused), every
# required field present, enum and type correctness, all cross-field rules, and
# a HandlerStrategyId that resolves against the closed v1 strategy ID set with a
# kind prefix consistent with the descriptor.

# Every field the pipeline reads. Presence of every one of these is mandatory.
$script:GraphOperationRequiredFields = @(
    'SchemaVersion', 'Type', 'Operation', 'OperationKind', 'HandlerStrategyId',
    'ApiVersion', 'Stability', 'BetaReason', 'Method', 'PathTemplate',
    'RequestBodyKind', 'ResponseKind', 'PagingStrategy', 'RequiredPagingHeaders',
    'DeduplicationKey', 'SupportsAll', 'SupportsDelta', 'ReplayPolicy', 'Condition',
    'Reconciliation', 'AdvancedQuery', 'Concurrency', 'CredentialPolicy', 'AllowedHosts',
    'RedirectPolicy', 'IdentityRequirement', 'ResourceFamily', 'ThrottleClass',
    'SupportedAuthModes', 'RequiredPermissions', 'RequiredLicense', 'SupportedClouds'
)

# Fields that must be non-empty strings (no enum).
$script:GraphOperationStringFields = @(
    'Type', 'Operation', 'Method', 'PathTemplate', 'ResponseKind', 'ResourceFamily'
)

# Fields that must be null or a non-empty string.
$script:GraphOperationNullableStringFields = @(
    'RequestBodyKind', 'BetaReason', 'DeduplicationKey'
)

# Fields that must be booleans.
$script:GraphOperationBoolFields = @(
    'SupportsAll', 'SupportsDelta'
)

# Fields that must be arrays (possibly empty).
$script:GraphOperationArrayFields = @(
    'RequiredPagingHeaders', 'AllowedHosts', 'SupportedAuthModes',
    'RequiredPermissions', 'RequiredLicense', 'SupportedClouds'
)

# Closed enums: field name -> allowed values.
$script:GraphOperationEnumFields = @(
    'OperationKind', 'ApiVersion', 'Stability', 'PagingStrategy', 'ReplayPolicy',
    'CredentialPolicy', 'RedirectPolicy', 'IdentityRequirement', 'ThrottleClass'
)

$script:GraphOperationEnums = @{
    OperationKind      = @('Collection', 'Singleton', 'Action', 'LongRunningJob', 'Binary', 'Scalar', 'NoContent', 'Delta')
    ApiVersion         = @('v1.0', 'beta')
    Stability          = @('Stable', 'DualVersion', 'BetaPreferred', 'BetaOnly')
    PagingStrategy     = @('None', 'NextLink')
    ReplayPolicy       = @('Safe', 'Conditional', 'Reconciliable', 'NeverReplay')
    CredentialPolicy   = @('GraphBearer', 'None')
    RedirectPolicy     = @('None', 'SafeGetOnly')
    IdentityRequirement = @('Verified', 'AllowUnverifiedRead')
    ThrottleClass      = @('Read', 'Write')
}

function Import-GraphOperationDescriptor {
    <#
        Loads a .psd1 operation descriptor with Import-PowerShellDataFile and
        validates it against the phase 1 descriptor schema, throwing an
        actionable error naming the file and every violated rule.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Operation descriptor file not found: '$Path'."
    }

    try {
        $descriptor = Import-PowerShellDataFile -LiteralPath $Path -ErrorAction Stop
    }
    catch {
        throw "Operation descriptor '$Path' could not be parsed as PowerShell data: $($_.Exception.Message)"
    }

    if ($descriptor -isnot [hashtable]) {
        throw "Operation descriptor '$Path' did not evaluate to a hashtable."
    }

    $violations = [System.Collections.Generic.List[string]]::new()

    # --- SchemaVersion -------------------------------------------------------
    if ($descriptor.ContainsKey('SchemaVersion')) {
        $schemaVersion = $descriptor['SchemaVersion']
        if ($schemaVersion -isnot [int]) {
            $violations.Add("Field 'SchemaVersion' must be an integer.")
        }
        elseif ($schemaVersion -gt 1) {
            $violations.Add("SchemaVersion $schemaVersion is newer than the supported version 1. Refusing to load this descriptor.")
        }
        elseif ($schemaVersion -lt 1) {
            $violations.Add("Field 'SchemaVersion' must be at least 1, got $schemaVersion.")
        }
    }

    # --- Required field presence --------------------------------------------
    foreach ($field in $script:GraphOperationRequiredFields) {
        if (-not $descriptor.ContainsKey($field)) {
            $violations.Add("Missing required field '$field'.")
        }
    }

    # --- Type checks ---------------------------------------------------------
    foreach ($field in $script:GraphOperationStringFields) {
        if ($descriptor.ContainsKey($field)) {
            $value = $descriptor[$field]
            if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) {
                $violations.Add("Field '$field' must be a non-empty string.")
            }
        }
    }

    foreach ($field in $script:GraphOperationNullableStringFields) {
        if ($descriptor.ContainsKey($field)) {
            $value = $descriptor[$field]
            if ($null -ne $value -and ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value))) {
                $violations.Add("Field '$field' must be null or a non-empty string.")
            }
        }
    }

    foreach ($field in $script:GraphOperationBoolFields) {
        if ($descriptor.ContainsKey($field)) {
            if ($descriptor[$field] -isnot [bool]) {
                $violations.Add("Field '$field' must be a boolean.")
            }
        }
    }

    foreach ($field in $script:GraphOperationArrayFields) {
        if ($descriptor.ContainsKey($field)) {
            $value = $descriptor[$field]
            if ($null -eq $value -or $value -isnot [System.Array]) {
                $violations.Add("Field '$field' must be an array.")
            }
        }
    }

    # --- Enum checks ---------------------------------------------------------
    foreach ($field in $script:GraphOperationEnumFields) {
        if ($descriptor.ContainsKey($field)) {
            $value = $descriptor[$field]
            if ($value -isnot [string] -or $value -notin $script:GraphOperationEnums[$field]) {
                $allowed = $script:GraphOperationEnums[$field] -join ', '
                $violations.Add("Field '$field' must be one of $allowed, got '$value'.")
            }
        }
    }

    # --- Nested hashtable shapes --------------------------------------------
    if ($descriptor.ContainsKey('AdvancedQuery')) {
        $advancedQuery = $descriptor['AdvancedQuery']
        if ($advancedQuery -isnot [hashtable]) {
            $violations.Add("Field 'AdvancedQuery' must be a hashtable with a boolean 'Supported' key.")
        }
        elseif (-not $advancedQuery.ContainsKey('Supported') -or $advancedQuery['Supported'] -isnot [bool]) {
            $violations.Add("Field 'AdvancedQuery' must contain a boolean 'Supported' key.")
        }
    }

    if ($descriptor.ContainsKey('Concurrency')) {
        $concurrency = $descriptor['Concurrency']
        if ($concurrency -isnot [hashtable]) {
            $violations.Add("Field 'Concurrency' must be a hashtable with keys Mode, Header, Required, and AllowWildcard.")
        }
        else {
            foreach ($key in @('Mode', 'Header', 'Required', 'AllowWildcard')) {
                if (-not $concurrency.ContainsKey($key)) {
                    $violations.Add("Field 'Concurrency' is missing required key '$key'.")
                }
            }
            if ($concurrency.ContainsKey('Mode') -and $concurrency['Mode'] -notin @('None', 'ETag', 'Header')) {
                $violations.Add("Field 'Concurrency.Mode' must be one of 'None', 'ETag', 'Header', got '$($concurrency['Mode'])'.")
            }
            if ($concurrency.ContainsKey('Required') -and $concurrency['Required'] -isnot [bool]) {
                $violations.Add("Field 'Concurrency.Required' must be a boolean.")
            }
            if ($concurrency.ContainsKey('AllowWildcard') -and $concurrency['AllowWildcard'] -isnot [bool]) {
                $violations.Add("Field 'Concurrency.AllowWildcard' must be a boolean.")
            }
        }
    }

    # --- Cross-field rules ---------------------------------------------------
    if ($descriptor.ContainsKey('CredentialPolicy') -and $descriptor['CredentialPolicy'] -eq 'None') {
        $allowedHosts = $descriptor['AllowedHosts']
        if (-not $descriptor.ContainsKey('AllowedHosts') -or $null -eq $allowedHosts -or @($allowedHosts).Count -eq 0) {
            $violations.Add("CredentialPolicy 'None' requires a non-empty AllowedHosts list.")
        }
        else {
            foreach ($allowedHost in @($allowedHosts)) {
                $parsed = $null
                $isHttps = $false
                if ($allowedHost -is [string] -and -not [string]::IsNullOrWhiteSpace($allowedHost)) {
                    $isHttps = [uri]::TryCreate($allowedHost, [System.UriKind]::Absolute, [ref]$parsed) -and $parsed.Scheme -eq 'https'
                }
                if (-not $isHttps) {
                    $violations.Add("CredentialPolicy 'None' requires HTTPS-only AllowedHosts entries; '$allowedHost' is not an https URL.")
                }
            }
        }
    }

    if ($descriptor.ContainsKey('Stability') -and $descriptor['Stability'] -in @('BetaPreferred', 'BetaOnly')) {
        $betaReason = $descriptor['BetaReason']
        if (-not $descriptor.ContainsKey('BetaReason') -or $null -eq $betaReason -or $betaReason -isnot [string] -or [string]::IsNullOrWhiteSpace($betaReason)) {
            $violations.Add("Stability '$($descriptor['Stability'])' requires a non-empty BetaReason.")
        }
    }

    if ($descriptor.ContainsKey('ReplayPolicy') -and $descriptor['ReplayPolicy'] -eq 'Reconciliable') {
        $reconciliation = $descriptor['Reconciliation']
        if (-not $descriptor.ContainsKey('Reconciliation') -or $null -eq $reconciliation -or $reconciliation -isnot [hashtable] -or $reconciliation.Count -eq 0) {
            $violations.Add("ReplayPolicy 'Reconciliable' requires a non-empty Reconciliation block.")
        }
    }

    if ($descriptor.ContainsKey('ReplayPolicy') -and $descriptor['ReplayPolicy'] -eq 'Conditional') {
        $condition = $descriptor['Condition']
        $conditionValid = $false
        if ($descriptor.ContainsKey('Condition') -and $condition -is [hashtable] -and
            $condition.ContainsKey('Method') -and $condition.ContainsKey('Precondition') -and $condition.ContainsKey('Cases')) {
            $method = $condition['Method']
            $precondition = $condition['Precondition']
            $cases = $condition['Cases']
            $conditionValid = ($method -is [string] -and -not [string]::IsNullOrWhiteSpace($method)) -and
                ($null -ne $precondition) -and
                ($null -ne $cases -and @($cases).Count -gt 0)
        }
        if (-not $conditionValid) {
            $violations.Add("ReplayPolicy 'Conditional' requires a Condition block naming the permitted Method, Precondition, and response/transport Cases.")
        }
    }

    if ($descriptor.ContainsKey('ApiVersion') -and $descriptor['ApiVersion'] -eq 'beta') {
        if ($descriptor.ContainsKey('Stability') -and $descriptor['Stability'] -notin @('DualVersion', 'BetaPreferred', 'BetaOnly')) {
            $violations.Add("ApiVersion 'beta' requires a beta-aware Stability (DualVersion, BetaPreferred, or BetaOnly), got '$($descriptor['Stability'])'.")
        }
    }

    if ($descriptor.ContainsKey('Stability') -and $descriptor['Stability'] -eq 'BetaOnly') {
        if ($descriptor.ContainsKey('ApiVersion') -and $descriptor['ApiVersion'] -ne 'beta') {
            $violations.Add("Stability 'BetaOnly' requires ApiVersion 'beta', got '$($descriptor['ApiVersion'])'.")
        }
    }

    if ($descriptor.ContainsKey('IdentityRequirement') -and $descriptor['IdentityRequirement'] -eq 'AllowUnverifiedRead') {
        if ($descriptor.ContainsKey('ThrottleClass') -and $descriptor['ThrottleClass'] -ne 'Read') {
            $violations.Add("IdentityRequirement 'AllowUnverifiedRead' requires ThrottleClass 'Read', got '$($descriptor['ThrottleClass'])'.")
        }
        if ($descriptor.ContainsKey('ReplayPolicy') -and $descriptor['ReplayPolicy'] -ne 'Safe') {
            $violations.Add("IdentityRequirement 'AllowUnverifiedRead' requires ReplayPolicy 'Safe', got '$($descriptor['ReplayPolicy'])'.")
        }
        if ($descriptor.ContainsKey('CredentialPolicy') -and $descriptor['CredentialPolicy'] -ne 'GraphBearer') {
            $violations.Add("IdentityRequirement 'AllowUnverifiedRead' requires CredentialPolicy 'GraphBearer', got '$($descriptor['CredentialPolicy'])'.")
        }
    }

    if ($descriptor.ContainsKey('PagingStrategy') -and $descriptor['PagingStrategy'] -eq 'NextLink') {
        # The other three paging fields (RequiredPagingHeaders, SupportsAll,
        # SupportsDelta) are enforced for presence and type by the global schema;
        # a NextLink operation additionally needs a real deduplication key.
        if ($descriptor.ContainsKey('DeduplicationKey')) {
            $deduplicationKey = $descriptor['DeduplicationKey']
            if ($null -eq $deduplicationKey -or $deduplicationKey -isnot [string] -or [string]::IsNullOrWhiteSpace($deduplicationKey)) {
                $violations.Add("PagingStrategy 'NextLink' requires a non-empty DeduplicationKey to deduplicate pages.")
            }
        }
    }

    # --- Handler strategy ID ------------------------------------------------
    if ($descriptor.ContainsKey('HandlerStrategyId') -and
        $descriptor.ContainsKey('OperationKind') -and
        $descriptor.ContainsKey('ReplayPolicy')) {
        $operationKind = $descriptor['OperationKind']
        $replayPolicy = $descriptor['ReplayPolicy']
        # Only enforce prefix consistency once the kind/policy enums are known valid;
        # otherwise their own violations already reject the descriptor.
        if ($operationKind -in $script:GraphOperationEnums['OperationKind'] -and
            $replayPolicy -in $script:GraphOperationEnums['ReplayPolicy']) {
            try {
                $null = Assert-GraphHandlerStrategyId -Id $descriptor['HandlerStrategyId'] -OperationKind $operationKind -ReplayPolicy $replayPolicy
            }
            catch {
                $violations.Add($_.Exception.Message)
            }
        }
    }

    if ($violations.Count -gt 0) {
        $detail = ($violations | ForEach-Object { "  - $_" }) -join [Environment]::NewLine
        throw "Operation descriptor '$Path' is invalid:$([Environment]::NewLine)$detail"
    }

    return $descriptor
}
