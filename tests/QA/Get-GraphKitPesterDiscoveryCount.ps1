[CmdletBinding()]
param([Parameter(Mandatory)][string] $RepositoryRoot)

$ErrorActionPreference = 'Stop'

$root = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).ProviderPath
$pesterManifest = Join-Path $root 'output/RequiredModules/Pester/6.1.0/Pester.psd1'
if (-not (Test-Path -LiteralPath $pesterManifest -PathType Leaf)) {
    throw "The repository-pinned Pester 6.1.0 manifest is missing at '$pesterManifest'."
}
Import-Module $pesterManifest -Force -ErrorAction Stop

$configuration = New-PesterConfiguration
$configuration.Run.Path = Join-Path $root 'tests'
$configuration.Run.SkipRun = $true
$configuration.Run.PassThru = $true
$configuration.Output.Verbosity = 'None'
$result = Invoke-Pester -Configuration $configuration
if ([string]$result.Result -cne 'Passed' -or @($result.FailedContainers).Count -ne 0) {
    $failureDetails = @($result.FailedContainers | ForEach-Object {
        "$($_.Item): $($_.ErrorRecord.Exception.Message)"
    }) -join '; '
    throw "Pester discovery did not complete cleanly: result=$($result.Result), failedContainers=$(@($result.FailedContainers).Count); $failureDetails"
}

$platform = if ($IsWindows) { 'Windows' } elseif ($IsLinux) { 'Linux' } elseif ($IsMacOS) { 'MacOS' } else { 'Unknown' }
[ordered]@{
    schemaVersion = 1
    platform = $platform
    total = [int]$result.TotalCount
    containers = @($result.Containers).Count
} | ConvertTo-Json -Compress
