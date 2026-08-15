# Operation catalog resolver (phase 1).
#
# Resolves validated operation descriptors from the module's Data/Operations
# directory. The catalog is loaded once per session into a script-scoped cache.
# The directory is located relative to $PSScriptRoot for both layouts: the built
# module (Data/Operations sits next to the .psm1) and the source tree (this file
# lives in source/Private/Operations, so Data/Operations is two levels up).

$script:GraphOperationCatalogCache = $null

function Get-GraphOperationsDirectory {
    <#
        Resolves the absolute path to the module's Data/Operations directory for
        both the built-module and source-tree layouts.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $candidates = [System.Collections.Generic.List[string]]::new()

    # Built module: Data/Operations sits beside the module root .psm1.
    $candidates.Add((Join-Path $PSScriptRoot 'Data/Operations'))

    # Source tree: source/Private/Operations -> source -> source/Data/Operations.
    $candidates.Add((Join-Path $PSScriptRoot '../../Data/Operations'))

    # Belt and braces: if the module is importable, prefer its module base.
    $module = Get-Module -Name GraphKit -ErrorAction SilentlyContinue
    if ($module) {
        $candidates.Add((Join-Path $module.ModuleBase 'Data/Operations'))
    }

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Container) {
            return (Resolve-Path -LiteralPath $candidate).ProviderPath
        }
    }

    throw "Could not locate the GraphKit Data/Operations directory. Looked in: $($candidates -join ', ')."
}

function Import-GraphOperationCatalog {
    <#
        Loads and validates every Data/Operations/*.psd1 descriptor once per
        session, caching the result in script scope.
    #>
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param()

    if ($null -ne $script:GraphOperationCatalogCache) {
        return $script:GraphOperationCatalogCache
    }

    $directory = Get-GraphOperationsDirectory
    $files = @(Get-ChildItem -LiteralPath $directory -Filter '*.psd1' -File -ErrorAction Stop | Sort-Object -Property Name)

    if ($files.Count -eq 0) {
        throw "No operation descriptor (.psd1) files found in '$directory'."
    }

    $catalog = @(foreach ($file in $files) {
        Import-GraphOperationDescriptor -Path $file.FullName
    })

    $script:GraphOperationCatalogCache = $catalog
    return $script:GraphOperationCatalogCache
}

function Get-GraphOperationInternal {
    <#
        Resolves one or more operation descriptors from the catalog.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [string] $Type,

        [Parameter()]
        [string] $Operation,

        [Parameter()]
        [switch] $List,

        [Parameter()]
        [string] $Cloud
    )

    $catalog = @(Import-GraphOperationCatalog)

    $results = $catalog

    if (-not [string]::IsNullOrWhiteSpace($Cloud)) {
        $results = @($results | Where-Object { $_.SupportedClouds -contains $Cloud })
    }

    if ($List) {
        return $results
    }

    if (-not [string]::IsNullOrWhiteSpace($Type) -and -not [string]::IsNullOrWhiteSpace($Operation)) {
        $match = @($results | Where-Object { $_['Type'] -eq $Type -and $_['Operation'] -eq $Operation })
        if ($match.Count -eq 1) {
            return $match[0]
        }
        if ($match.Count -gt 1) {
            throw "Multiple operation descriptors match Type '$Type' Operation '$Operation'; the catalog is ambiguous."
        }
        $pairs = @($catalog | ForEach-Object { "$($_['Type'])/$($_['Operation'])" } | Sort-Object -Unique)
        throw "No operation descriptor for Type '$Type' Operation '$Operation'. Available Type/Operation pairs: $($pairs -join ', ')."
    }

    if (-not [string]::IsNullOrWhiteSpace($Type)) {
        $match = @($results | Where-Object { $_['Type'] -eq $Type })
        if ($match.Count -eq 0) {
            $types = @($catalog | ForEach-Object { $_['Type'] } | Sort-Object -Unique)
            throw "No operation descriptors for Type '$Type'. Available Types: $($types -join ', ')."
        }
        return $match
    }

    if (-not [string]::IsNullOrWhiteSpace($Operation)) {
        $match = @($results | Where-Object { $_['Operation'] -eq $Operation })
        if ($match.Count -eq 0) {
            $operations = @($catalog | ForEach-Object { $_['Operation'] } | Sort-Object -Unique)
            throw "No operation descriptors for Operation '$Operation'. Available Operations: $($operations -join ', ')."
        }
        return $match
    }

    return $results
}
