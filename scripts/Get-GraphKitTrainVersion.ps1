[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $RepositoryRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).ProviderPath
$base = '0.4.0'
$train = 'r8'
$revision = (& git -C $RepositoryRoot rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $revision -notmatch '^[0-9a-f]{40}$') {
    throw "Cannot resolve a 40-character source revision for '$RepositoryRoot'."
}
$diff = (& git -C $RepositoryRoot diff --binary HEAD)
if ($LASTEXITCODE -ne 0) {
    throw "Cannot determine whether '$RepositoryRoot' has uncommitted source changes."
}
$suffix = if ([string]::IsNullOrEmpty($diff)) {
    ''
}
else {
    $bytes = [Text.Encoding]::UTF8.GetBytes($diff)
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    ".d$($hash.Substring(0, 12))"
}
"$base-$train.g$($revision.Substring(0, 12))$suffix"
