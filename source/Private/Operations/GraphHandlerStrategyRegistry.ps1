# Handler strategy registry (phase 1 machinery).
#
# Strategy IDs follow '<Kind>.<StrategyName>' where 'Kind' is a handler kind:
# 'Collection', 'Action', 'Reconciliation', and 'LongRunningJob'. The closed v1
# ID set below is authoritative. Descriptor files reference strategy IDs and are
# validated against this set (never against whatever instances happen to be
# registered), so catalog load succeeds before any implementation exists.
#
# Registering the actual strategy implementations is the pipeline slice's job
# (slice 5). This file supplies the registry machinery and the ID validation
# that the descriptor loader depends on.

# The closed v1 strategy ID set. Handlers for these IDs are registered by
# private module code (slice 5); descriptors may only reference IDs in this set.
$script:GraphKnownHandlerStrategyIds = @(
    'Collection.Default'
    'Action.Default'
    'Reconciliation.StableExternalKey'
    'LongRunningJob.PollStatus'
)

# Kind-prefix constraints. 'Collection', 'Action', and 'LongRunningJob' map 1:1
# to OperationKind. 'Reconciliation' is a replay-semantics handler tied to
# ReplayPolicy = Reconciliable (its operations are still shaped as Action or
# Collection), so it maps to ReplayPolicy rather than an OperationKind.
$script:GraphHandlerStrategyKindConstraints = @{
    'Collection'     = @{ OperationKind = 'Collection' }
    'Action'         = @{ OperationKind = 'Action' }
    'Reconciliation' = @{ ReplayPolicy = 'Reconciliable' }
    'LongRunningJob' = @{ OperationKind = 'LongRunningJob' }
}

# Registered strategy instances. Keys are strategy IDs; values are scriptblocks
# invoked as (& $handler -Context ... -Descriptor ... -Parameters ... -Transport ...).
$script:GraphHandlerStrategyRegistry = @{}

function Register-GraphHandlerStrategy {
    <#
        Registers a handler strategy implementation under a closed v1 strategy ID.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Id,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [scriptblock] $Handler
    )

    if ($Id -notin $script:GraphKnownHandlerStrategyIds) {
        throw "Handler strategy '$Id' is not a known v1 strategy. Known strategies: $($script:GraphKnownHandlerStrategyIds -join ', ')."
    }

    $script:GraphHandlerStrategyRegistry[$Id] = $Handler
}

function Resolve-GraphHandlerStrategy {
    <#
        Resolves a registered handler strategy by ID, validating the kind prefix
        against the closed v1 ID set before lookup.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Id
    )

    if ($Id -notin $script:GraphKnownHandlerStrategyIds) {
        throw "Handler strategy '$Id' is not a known v1 strategy. v1 strategy IDs use the kind prefixes Collection, Action, Reconciliation, or LongRunningJob. Known strategies: $($script:GraphKnownHandlerStrategyIds -join ', ')."
    }

    if (-not $script:GraphHandlerStrategyRegistry.ContainsKey($Id)) {
        throw "Handler strategy '$Id' is a known v1 strategy but has not been registered."
    }

    return $script:GraphHandlerStrategyRegistry[$Id]
}

function Assert-GraphHandlerStrategyId {
    <#
        Validates that a HandlerStrategyId belongs to the closed v1 set and that
        its kind prefix is consistent with the descriptor's OperationKind and
        ReplayPolicy. Throws an actionable error on the first violation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Id,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $OperationKind,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $ReplayPolicy
    )

    if ($Id -notin $script:GraphKnownHandlerStrategyIds) {
        throw "HandlerStrategyId '$Id' is not a known v1 strategy. Known strategies: $($script:GraphKnownHandlerStrategyIds -join ', ')."
    }

    $kind = $Id.Substring(0, $Id.IndexOf('.'))
    $constraint = $script:GraphHandlerStrategyKindConstraints[$kind]

    if ($constraint.ContainsKey('OperationKind') -and $constraint['OperationKind'] -ne $OperationKind) {
        throw "HandlerStrategyId '$Id' has kind prefix '$kind', which requires OperationKind '$($constraint['OperationKind'])', but the descriptor declares OperationKind '$OperationKind'."
    }

    if ($constraint.ContainsKey('ReplayPolicy') -and $constraint['ReplayPolicy'] -ne $ReplayPolicy) {
        throw "HandlerStrategyId '$Id' has kind prefix '$kind', which requires ReplayPolicy '$($constraint['ReplayPolicy'])', but the descriptor declares ReplayPolicy '$ReplayPolicy'."
    }

    return $true
}
