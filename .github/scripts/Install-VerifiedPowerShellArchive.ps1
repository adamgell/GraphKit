[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $Version,
    [Parameter(Mandatory)][string] $AssetName,
    [Parameter(Mandatory)][string] $ArchivePath,
    [Parameter(Mandatory)][string] $InstallDirectory,
    [Parameter(Mandatory)][string] $HashMapPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$hashMap = Get-Content -LiteralPath $HashMapPath -Raw | ConvertFrom-Json -AsHashtable
if ([int]$hashMap.schemaVersion -ne 1) {
    throw 'The reviewed PowerShell release hash map has an unsupported schema version.'
}
$key = "$Version/$AssetName"
$matchingKeys = @($hashMap.sha256.Keys | Where-Object { [string]$_ -ceq $key })
if ($matchingKeys.Count -ne 1) {
    throw "PowerShell release asset '$key' has no reviewed SHA-256 mapping."
}
$expectedHash = [string]$hashMap.sha256[$matchingKeys[0]]
if ($expectedHash -cnotmatch '^[0-9a-f]{64}$') {
    throw "The reviewed digest for PowerShell release asset '$key' is not a lowercase 64-character SHA-256."
}
$actualHash = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
if (-not [string]::Equals($actualHash, $expectedHash, [StringComparison]::Ordinal)) {
    throw "PowerShell release asset '$key' does not match its reviewed SHA-256."
}
Write-Host "Verified SHA-256 for $AssetName."

$null = New-Item -ItemType Directory -Path $InstallDirectory -Force
if ($AssetName.EndsWith('.zip', [StringComparison]::Ordinal)) {
    Expand-Archive -LiteralPath $ArchivePath -DestinationPath $InstallDirectory -Force
}
elseif ($AssetName.EndsWith('.tar.gz', [StringComparison]::Ordinal)) {
    & tar -xzf $ArchivePath -C $InstallDirectory
    if ($LASTEXITCODE -ne 0) { throw "PowerShell archive extraction failed for '$AssetName'." }
}
else {
    throw "PowerShell release asset '$AssetName' is not a supported archive."
}
