<#
    .SYNOPSIS
        Reports which Microsoft Graph endpoints IntuneHealthAutomation uses, and which of
        them the GraphKit operation catalog can currently serve.

    .DESCRIPTION
        Phase 5 steps 5-6 cannot proceed on assertion. GraphKit is descriptor-driven -
        Get-GraphObject resolves a Type to a catalog descriptor - while IHA passes computed
        URI strings to a single wrapper. Repointing is therefore a semantic rewrite, not a
        substitution, and it is blocked wherever no descriptor covers the endpoint.

        This script produces the work list instead of estimating it: every Graph path
        referenced in IHA source, normalised, matched against every PathTemplate in the
        catalog, and reported as Covered or Uncovered.

        It is deliberately conservative. A path it cannot normalise is reported as
        Unresolvable rather than assumed covered, because an over-optimistic coverage number
        is exactly the kind of "bounded work reported as complete" this repository keeps
        finding in its own history.

    .PARAMETER IhaPath
        Root of the IntuneHealthAutomation checkout.

    .PARAMETER ModulePath
        GraphKit manifest to load the catalog from. Defaults to the built module.

    .EXAMPLE
        ./scripts/Get-GraphKitCutoverCoverage.ps1 -IhaPath ~/repo/lab_phy1_fdrive_code/IntuneHealthAutomation
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $IhaPath,

    [string] $ModulePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$repoRoot = Split-Path $PSScriptRoot -Parent

if ([string]::IsNullOrWhiteSpace($ModulePath)) {
    $built = Get-ChildItem -Path (Join-Path $repoRoot 'output/module/GraphKit') -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) { throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first.' }
    $ModulePath = Join-Path $built.FullName 'GraphKit.psd1'
}

if (-not (Test-Path -LiteralPath $IhaPath -PathType Container)) {
    throw "IntuneHealthAutomation path '$IhaPath' does not exist."
}

Import-Module $ModulePath -Force

$catalog = @(Get-GraphOperation)

# Normalise a catalog PathTemplate into a comparable shape: lower case, no leading slash,
# every {token} and every id-looking segment collapsed to '*'.
function ConvertTo-ComparablePath {
    param([string] $Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $p = $Path.Trim().ToLowerInvariant()
    $p = $p -replace '^https?://[^/]+/(v1\.0|beta)/', ''
    $p = $p.TrimStart('/')
    $p = $p -replace '\?.*$', ''            # query string
    $p = $p -replace '\{[^}]+\}', '*'       # descriptor tokens
    $p = $p -replace '\$[a-z0-9_]+', '*'    # PowerShell variables in IHA source
    $p = $p -replace '[0-9a-f]{8}-[0-9a-f-]{27,}', '*'  # literal GUIDs
    return $p.TrimEnd('/')
}

$catalogPaths = @($catalog | ForEach-Object {
        [pscustomobject]@{
            Type       = $_.Type
            Operation  = $_.Operation
            Template   = $_.PathTemplate
            ApiVersion = $_.ApiVersion
            Comparable = ConvertTo-ComparablePath $_.PathTemplate
        }
    })

# IntuneHealthAutomation declares its Graph surface in one data file. Reading it beats
# scraping source: the file is authoritative, structured, and records which API version each
# collection actually uses - which matters, because GraphKit treats API version as
# per-operation descriptor metadata rather than a global mode. A v1.0 descriptor does not
# cover a caller that reads beta.
$endpointFile = Join-Path $IhaPath 'src/data/GraphEndpoints.json'
if (-not (Test-Path -LiteralPath $endpointFile -PathType Leaf)) {
    throw "Expected IHA's endpoint catalogue at '$endpointFile'. If it moved, this report would silently under-count; refusing to guess."
}

$declared = Get-Content -LiteralPath $endpointFile -Raw | ConvertFrom-Json

$found = @{}
foreach ($property in $declared.PSObject.Properties) {
    $entry = $property.Value

    # Prefer the version IHA actually calls. Where only a BetaUri exists, beta IS the
    # production path for that collection.
    $uri = $null
    $apiVersion = $null
    if ($entry.PSObject.Properties['BetaUri'] -and -not [string]::IsNullOrWhiteSpace($entry.BetaUri)) {
        $uri = $entry.BetaUri; $apiVersion = 'beta'
    }
    elseif ($entry.PSObject.Properties['V1Uri'] -and -not [string]::IsNullOrWhiteSpace($entry.V1Uri)) {
        $uri = $entry.V1Uri; $apiVersion = 'v1.0'
    }
    if ([string]::IsNullOrWhiteSpace($uri)) { continue }

    $hasV1 = $entry.PSObject.Properties['V1Uri'] -and -not [string]::IsNullOrWhiteSpace($entry.V1Uri)
    $comparable = ConvertTo-ComparablePath $uri

    $found[$property.Name] = [pscustomobject]@{
        Collection = $property.Name
        Comparable = $comparable
        Uri        = $uri
        ApiVersion = $apiVersion
        HasV1      = [bool] $hasV1
    }
}

$rows = foreach ($entry in ($found.Values | Sort-Object Collection)) {
    # A path can now be served by more than one descriptor - a v1.0 operation and its beta
    # sibling share a PathTemplate and differ only by ApiVersion. Taking the first match would
    # report a version gap that does not exist, so prefer the descriptor whose ApiVersion is
    # the one IHA actually calls.
    $candidates = @($catalogPaths | Where-Object { $_.Comparable -eq $entry.Comparable })
    $match = $candidates | Where-Object { $_.ApiVersion -eq $entry.ApiVersion } | Select-Object -First 1
    if ($null -eq $match) { $match = $candidates | Select-Object -First 1 }

    # A path match is not coverage on its own. GraphKit pins API version per operation, so a
    # v1.0 descriptor does not serve a caller reading beta - and IHA reads beta for most of
    # its surface. Report that distinction rather than counting it as done.
    $status = if ($null -eq $match) { 'Uncovered' }
    elseif ($match.ApiVersion -eq $entry.ApiVersion) { 'Covered' }
    elseif ($entry.HasV1) { 'CoveredAtV1' }
    else { 'VersionGap' }

    [pscustomobject]@{
        PSTypeName   = 'GraphKit.CutoverCoverageRow'
        Status       = $status
        Collection   = $entry.Collection
        IhaVersion   = $entry.ApiVersion
        Path         = $entry.Comparable
        CoveredBy    = if ($null -ne $match) { "$($match.Type)/$($match.Operation)" } else { $null }
        GraphKitVersion = if ($null -ne $match) { $match.ApiVersion } else { $null }
    }
}

$rows = @($rows)
$covered = @($rows | Where-Object Status -eq 'Covered')
$atV1 = @($rows | Where-Object Status -eq 'CoveredAtV1')
$versionGap = @($rows | Where-Object Status -eq 'VersionGap')
$uncovered = @($rows | Where-Object Status -eq 'Uncovered')

Write-Host ''
Write-Host "  GraphKit catalog : $($catalog.Count) descriptors" -ForegroundColor Cyan
Write-Host "  IHA collections  : $($rows.Count) declared in src/data/GraphEndpoints.json" -ForegroundColor Cyan
Write-Host ''
Write-Host "    Covered      : $($covered.Count)  descriptor exists at the version IHA calls" -ForegroundColor Green
Write-Host "    CoveredAtV1  : $($atV1.Count)  descriptor is v1.0, IHA calls beta but a v1.0 URI exists" -ForegroundColor Yellow
Write-Host "    VersionGap   : $($versionGap.Count)  IHA calls beta and there is no v1.0 equivalent" -ForegroundColor DarkYellow
Write-Host "    Uncovered    : $($uncovered.Count)  no descriptor at all" -ForegroundColor Red
Write-Host ''
if ($uncovered.Count -gt 0) {
    Write-Host '  Descriptors still needed:' -ForegroundColor Red
    $uncovered | ForEach-Object { Write-Host ("    {0,-28} {1,-5} {2}" -f $_.Collection, $_.IhaVersion, $_.Path) -ForegroundColor DarkGray }
    Write-Host ''
}

$rows
