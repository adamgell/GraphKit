# Argument completers for the operation catalog (phase 2).
#
# Registers tab completion for the -Type and -Operation parameters of the
# catalog entry points (Get-GraphObject, Invoke-GraphOperation,
# Get-GraphOperation). Completion values are enumerated live from the operation
# catalog at completion time, so a newly added descriptor file is completable
# immediately after import with no other edit. The scriptblocks run in the
# module session state, where Import-GraphOperationCatalog is resolved.

$script:GraphTypeCompleter = {
    # Register-ArgumentCompleter invokes the block with five positional arguments:
    # commandName, parameterName, wordToComplete, commandAst, fakeBoundParameters.
    $wordToComplete = $args[2]

    $types = @(Import-GraphOperationCatalog | ForEach-Object { $_['Type'] } | Sort-Object -Unique)
    foreach ($type in $types) {
        if ([string]::IsNullOrEmpty($wordToComplete) -or
            ([string] $type).StartsWith([string] $wordToComplete, [System.StringComparison]::OrdinalIgnoreCase)) {
            [System.Management.Automation.CompletionResult]::new($type, $type, 'ParameterValue', $type)
        }
    }
}

$script:GraphOperationCompleter = {
    # Same five-positional-argument contract as GraphTypeCompleter.
    $wordToComplete = $args[2]
    $fakeBoundParameters = $args[4]

    $catalog = @(Import-GraphOperationCatalog)

    $typeFilter = $null
    if ($null -ne $fakeBoundParameters -and $fakeBoundParameters.ContainsKey('Type')) {
        $typeFilter = [string] $fakeBoundParameters['Type']
    }

    $source = if ([string]::IsNullOrWhiteSpace($typeFilter)) {
        $catalog
    } else {
        @($catalog | Where-Object { $_['Type'] -eq $typeFilter })
    }

    $operations = @($source | ForEach-Object { $_['Operation'] } | Sort-Object -Unique)

    foreach ($operation in $operations) {
        if ([string]::IsNullOrEmpty($wordToComplete) -or
            ([string] $operation).StartsWith([string] $wordToComplete, [System.StringComparison]::OrdinalIgnoreCase)) {
            [System.Management.Automation.CompletionResult]::new($operation, $operation, 'ParameterValue', $operation)
        }
    }
}

function Register-GraphArgumentCompleter {
    <#
        Registers the catalog argument completers for the catalog entry points.
    #>
    [CmdletBinding()]
    param()

    $targets = @(
        'Get-GraphObject'
        'Invoke-GraphOperation'
        'Get-GraphOperation'
    )

    foreach ($commandName in $targets) {
        Register-ArgumentCompleter -CommandName $commandName -ParameterName 'Type' -ScriptBlock $script:GraphTypeCompleter
        Register-ArgumentCompleter -CommandName $commandName -ParameterName 'Operation' -ScriptBlock $script:GraphOperationCompleter
    }
}

# Register at import.
Register-GraphArgumentCompleter
