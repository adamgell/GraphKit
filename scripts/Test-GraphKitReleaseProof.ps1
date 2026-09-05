<#
    .SYNOPSIS
        Verifies that a GraphKit package is the exact artifact bound to a passing test run.

    .DESCRIPTION
        Validates the canonical output/testResults/tested-release-proof.json record. The
        proof binds one module version, the exact package archive, the NUnit/Pester result
        pair and its whole-result policy, and the SHA-256 of every shipped module file.
        Both GraphKit publication paths call this script; neither maintains an independent
        or weaker definition of "tested release".

    .PARAMETER PackagePath
        The already-built GraphKit .nupkg to verify.

    .PARAMETER ProofPath
        The canonical proof. Defaults to output/testResults/tested-release-proof.json.

    .PARAMETER TestResultPath
        Optional operator-supplied NUnit result. When supplied, it must be the exact file
        named and hashed by the proof; a separate same-version result is not accepted.

    .PARAMETER RepositoryRoot
        Repository root containing output/ and tests/. Defaults to this script's parent.
        The override permits offline verification of a relocated release evidence bundle.

    .PARAMETER VerifiedPackageCopyPath
        Optional caller-owned destination for a snapshot of the exact verified package.
        Publication scripts use this snapshot so a concurrent replacement of PackagePath
        cannot change the bytes after verification.

    .PARAMETER VerifiedProofCopyPath
        Optional caller-owned destination for a snapshot of the exact verified proof.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $PackagePath,

    [string] $ProofPath,

    [string] $TestResultPath,

    [string] $RepositoryRoot,

    [string] $VerifiedPackageCopyPath,

    [string] $VerifiedProofCopyPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$minimumTests = 1463
$allowedSkips = 0
$allowedNotRun = 0

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Split-Path $PSScriptRoot -Parent
}
$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).ProviderPath

if ([string]::IsNullOrWhiteSpace($ProofPath)) {
    $ProofPath = Join-Path $RepositoryRoot 'output/testResults/tested-release-proof.json'
}

if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) {
    throw "Package '$PackagePath' does not exist."
}
$package = Get-Item -LiteralPath $PackagePath
if ($package.Extension -cne '.nupkg') {
    throw "Package '$PackagePath' is not a .nupkg."
}
if ($package.BaseName -notmatch '^(?<name>.+?)\.(?<version>\d+\.\d+\.\d+(?:-[A-Za-z0-9.\-]+)?)$') {
    throw "Cannot parse a module name and version from '$($package.Name)'."
}
$moduleName = $Matches['name']
$moduleVersion = $Matches['version']
if ($moduleName -cne 'GraphKit') {
    throw "Package '$($package.Name)' is '$moduleName', not GraphKit."
}

if (-not (Test-Path -LiteralPath $ProofPath -PathType Leaf)) {
    throw "No tested release proof found at '$ProofPath'. Run ./build.ps1 -Tasks pack then ./build.ps1 -Tasks test."
}
$initialProofHash = (Get-FileHash -LiteralPath $ProofPath -Algorithm SHA256).Hash.ToLowerInvariant()
try {
    $proof = Get-Content -LiteralPath $ProofPath -Raw | ConvertFrom-Json -Depth 10
    $proofSchemaVersion = [int] $proof.schemaVersion
    $proofRunId = [string] $proof.runId
    $proofSourceRevision = [string] $proof.source.revision
    $proofSourceClean = $proof.source.clean
    $proofSourceStateHash = [string] $proof.source.stateSha256
    $proofModuleName = [string] $proof.module.name
    $proofModuleVersion = [string] $proof.module.version
    $proofModuleBaseVersion = [string] $proof.module.baseVersion
    $proofModuleFiles = @($proof.module.files)
    $proofPackageName = [string] $proof.package.name
    $proofPackageHash = [string] $proof.package.sha256
    $proofNUnitName = [string] $proof.testRun.nunit.name
    $proofNUnitHash = [string] $proof.testRun.nunit.sha256
    $proofPesterObjectName = [string] $proof.testRun.pesterObject.name
    $proofPesterObjectHash = [string] $proof.testRun.pesterObject.sha256
    $proofMinimumTests = [int] $proof.testRun.policy.minimumTests
    $proofAllowedSkips = [int] $proof.testRun.policy.allowedSkips
    $proofAllowedNotRun = [int] $proof.testRun.policy.allowedNotRun
    $proofSummary = $proof.testRun.summary
}
catch {
    throw "The tested release proof '$ProofPath' is unreadable or incomplete: $($_.Exception.Message)"
}

$parsedRunId = [guid]::Empty
if ($proofSchemaVersion -ne 3 -or
    -not [guid]::TryParse($proofRunId, [ref] $parsedRunId) -or
    $parsedRunId -eq [guid]::Empty) {
    throw "The tested release proof '$ProofPath' has an unsupported schema version or invalid run id."
}
if ($proofSourceRevision -notmatch '^[0-9a-f]{40}$' -or $proofSourceClean -isnot [bool]) {
    throw "The tested release proof '$ProofPath' has invalid source provenance."
}
if ($proofSourceStateHash -notmatch '^[0-9a-f]{64}$') {
    throw "The tested release proof '$ProofPath' has no valid canonical source-state hash."
}
$expectedProofVersion = "0.4.0-r8.g$($proofSourceRevision.Substring(0, 12))"
if (-not $proofSourceClean) {
    $expectedProofVersion += ".d$($proofSourceStateHash.Substring(0, 12))"
}
if ($proofModuleBaseVersion -cne '0.4.0') {
    throw "The tested release proof '$ProofPath' requires the R8 base '0.4.0' and train 'r8'."
}
if ($proofModuleVersion -cne $expectedProofVersion) {
    throw "The tested release proof '$ProofPath' does not bind its module version to source provenance."
}
if (-not $proofSourceClean) {
    throw "The tested release proof '$ProofPath' represents dirty source state and is non-authoritative: it cannot produce VERIFIED TESTED RELEASE authority, snapshots, or publication input."
}
if ($proofModuleName -cne $moduleName -or $proofModuleVersion -cne $moduleVersion) {
    throw "The tested release proof names '$proofModuleName' $proofModuleVersion, not '$moduleName' $moduleVersion."
}
if ($proofPackageName -cne $package.Name -or $proofPackageHash -notmatch '^[0-9a-fA-F]{64}$') {
    throw "The tested release proof does not name a valid hash for package '$($package.Name)'."
}
$proofPackageHash = $proofPackageHash.ToLowerInvariant()

if ($proofMinimumTests -ne $minimumTests -or
    $proofAllowedSkips -ne $allowedSkips -or
    $proofAllowedNotRun -ne $allowedNotRun) {
    throw "The tested release proof carries a weakened or stale whole-result policy. Expected minimumTests=$minimumTests, allowedSkips=$allowedSkips, allowedNotRun=$allowedNotRun."
}

$proofFileMap = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$proofNormalizedPathMap = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($fileRecord in $proofModuleFiles) {
    try {
        $relativePath = [string] $fileRecord.path
        $relativeHash = [string] $fileRecord.sha256
    }
    catch {
        throw "The tested release proof contains an incomplete module-file record."
    }

    $segments = @($relativePath -split '/')
    if ([string]::IsNullOrWhiteSpace($relativePath) -or
        [System.IO.Path]::IsPathRooted($relativePath) -or
        $relativePath -match '^[A-Za-z]:' -or
        $relativePath.IndexOf('\') -ge 0 -or
        $segments -contains '' -or
        $segments -contains '.' -or
        $segments -contains '..' -or
        $relativeHash -notmatch '^[0-9a-fA-F]{64}$') {
        throw "The tested release proof contains an invalid module-file record for '$relativePath'."
    }
    if (-not $proofFileMap.TryAdd($relativePath, $relativeHash.ToLowerInvariant())) {
        throw "The tested release proof contains a duplicate or case-colliding module-file record for '$relativePath'."
    }
    $normalizedPath = $relativePath.Normalize([Text.NormalizationForm]::FormC)
    if ($relativePath -cne $normalizedPath -or
        -not $proofNormalizedPathMap.TryAdd($normalizedPath, $relativePath)) {
        throw "The tested release proof contains a Unicode-normalization or NFC-colliding module-file record for '$relativePath'."
    }
}
if ($proofFileMap.Count -eq 0) {
    throw 'The tested release proof records zero shipped module files.'
}

$builtModuleDirectory = Join-Path $RepositoryRoot "output/module/GraphKit/$proofModuleBaseVersion"
if (-not (Test-Path -LiteralPath $builtModuleDirectory -PathType Container)) {
    throw "The built module directory '$builtModuleDirectory' is missing."
}

[string[]] $currentRelativePaths = @(
    Get-ChildItem -LiteralPath $builtModuleDirectory -Recurse -File -Force |
        ForEach-Object {
            $_.FullName.Substring($builtModuleDirectory.Length + 1) -replace '\\', '/'
        }
)
[System.Array]::Sort($currentRelativePaths, [System.StringComparer]::Ordinal)
$currentPathMap = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$currentNormalizedPathMap = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($relativePath in $currentRelativePaths) {
    $normalizedPath = $relativePath.Normalize([Text.NormalizationForm]::FormC)
    if ($relativePath -cne $normalizedPath -or
        -not $currentPathMap.TryAdd($relativePath, $relativePath) -or
        -not $currentNormalizedPathMap.TryAdd($normalizedPath, $relativePath)) {
        throw "The built module contains case- or Unicode-normalization-colliding paths for '$relativePath'."
    }
}

$missingPaths = @($proofFileMap.Keys | Where-Object { -not $currentPathMap.ContainsKey([string] $_) })
$extraPaths = @($currentRelativePaths | Where-Object { -not $proofFileMap.ContainsKey($_) })
$caseChangedPaths = @(
    $proofFileMap.Keys | Where-Object {
        $currentPathMap.ContainsKey([string] $_) -and
        -not [string]::Equals([string] $_, $currentPathMap[[string] $_], [System.StringComparison]::Ordinal)
    }
)
if ($missingPaths.Count -gt 0 -or $extraPaths.Count -gt 0 -or $caseChangedPaths.Count -gt 0) {
    $details = @(
        $missingPaths | ForEach-Object { "missing:$_" }
        $extraPaths | ForEach-Object { "extra:$_" }
        $caseChangedPaths | ForEach-Object { "case:$($_)->$($currentPathMap[[string] $_])" }
    ) -join ', '
    throw "The built module file set differs from the tested release proof ($details)."
}

foreach ($relativePath in $proofFileMap.Keys) {
    $currentPath = Join-Path $builtModuleDirectory $relativePath
    $currentHash = (Get-FileHash -LiteralPath $currentPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($currentHash -cne $proofFileMap[$relativePath]) {
        throw "'$relativePath' in the built module does not match the tested release proof."
    }
}

$builtManifestPath = Join-Path $builtModuleDirectory 'GraphKit.psd1'
if (-not (Test-Path -LiteralPath $builtManifestPath -PathType Leaf)) {
    throw "The built module file set differs from the tested release proof (missing:GraphKit.psd1)."
}
$builtManifest = Import-PowerShellDataFile -LiteralPath $builtManifestPath
if ([string] $builtManifest.ModuleVersion -cne $proofModuleBaseVersion) {
    throw "The built GraphKit.psd1 declares version '$($builtManifest.ModuleVersion)', not proof base version '$proofModuleBaseVersion'."
}
$expectedPrerelease = $moduleVersion.Substring($proofModuleBaseVersion.Length + 1)
if ([string] $builtManifest.PrivateData.PSData.Prerelease -cne $expectedPrerelease) {
    throw "The built GraphKit.psd1 prerelease '$($builtManifest.PrivateData.PSData.Prerelease)' does not match proof version '$moduleVersion'."
}

$graphKitAuthContractPath = 'Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll'
$builtRequiredAssemblies = if ($builtManifest -is [Collections.IDictionary] -and
    $builtManifest.Contains('RequiredAssemblies')) {
    @($builtManifest['RequiredAssemblies'] | ForEach-Object { [string]$_ })
}
else {
    @()
}
$proofGraphKitAuthPaths = @($proofFileMap.Keys | Where-Object { $_.StartsWith('Assemblies/GraphKit.Auth/', [StringComparison]::Ordinal) })
$verifiedGraphKitAuthStage = $null
if (($builtRequiredAssemblies -join '|') -ceq $graphKitAuthContractPath) {
    $taskPath = Join-Path $RepositoryRoot '.build/GraphKitAuth.tasks.ps1'
    $helperPath = Join-Path $RepositoryRoot 'scripts/private/GraphKit.AuthStageCapture.cs'
    if (-not (Test-Path -LiteralPath $taskPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $helperPath -PathType Leaf)) {
        throw 'The built GraphKit.Auth prerequisite has no tracked sealed-stage verifier.'
    }
    . $taskPath -SkipTaskRegistration
    $stageVersionRoot = Join-Path $RepositoryRoot "output/GraphKit.Auth/stage/$moduleVersion"
    if (-not (Test-Path -LiteralPath $stageVersionRoot -PathType Container)) {
        throw "The sealed GraphKit.Auth stage for '$moduleVersion' is missing."
    }
    $stageEntries = @([IO.Directory]::EnumerateFileSystemEntries($stageVersionRoot))
    if ($stageEntries.Count -ne 1 -or -not (Test-Path -LiteralPath $stageEntries[0] -PathType Container)) {
        throw "The sealed GraphKit.Auth stage for '$moduleVersion' is not one exact digest envelope."
    }
    $verifiedGraphKitAuthStage = Test-GraphKitAuthSealedStage -StagePath $stageEntries[0] -FullVersion $moduleVersion
    $stageModulePaths = @($verifiedGraphKitAuthStage.Manifest.files | ForEach-Object {
        "Assemblies/GraphKit.Auth/$([IO.Path]::GetFileName([string]$_.path))"
    })
    $proofGraphKitAuthSet = @($proofGraphKitAuthPaths | Sort-Object) -join '|'
    $stageGraphKitAuthSet = @($stageModulePaths | Sort-Object) -join '|'
    if ($proofGraphKitAuthSet -cne $stageGraphKitAuthSet) {
        throw 'The tested release proof GraphKit.Auth subtree does not match the sealed five-file manifest.'
    }
    foreach ($stageFile in @($verifiedGraphKitAuthStage.Manifest.files)) {
        $modulePath = "Assemblies/GraphKit.Auth/$([IO.Path]::GetFileName([string]$stageFile.path))"
        if (-not $proofFileMap.ContainsKey($modulePath) -or
            $proofFileMap[$modulePath] -cne [string]$stageFile.sha256) {
            throw "The tested release proof '$modulePath' digest does not match the sealed GraphKit.Auth stage."
        }
    }
}
elseif ($proofGraphKitAuthPaths.Count -ne 0) {
    throw 'The tested release proof contains GraphKit.Auth runtime bytes without the exact built contracts prerequisite.'
}

$currentPackageHash = (Get-FileHash -LiteralPath $package.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
if ($currentPackageHash -cne $proofPackageHash) {
    throw "The '$($package.Name)' package archive changed after the passing test run."
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($package.FullName)
try {
    $wrapperPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($wrapperPath in @(
        "$moduleName.nuspec",
        '[Content_Types].xml',
        '_rels/.rels'
    )) {
        $null = $wrapperPaths.Add($wrapperPath)
    }

    $archivePathMap = [System.Collections.Generic.Dictionary[string, System.IO.Compression.ZipArchiveEntry]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $archiveNormalizedPathMap = [System.Collections.Generic.Dictionary[string, string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($entry in $archive.Entries) {
        $entryPath = [string] $entry.FullName
        $segments = @($entryPath -split '/')
        if ([string]::IsNullOrWhiteSpace($entryPath) -or
            [string]::IsNullOrEmpty($entry.Name) -or
            $entryPath.EndsWith('/') -or
            [System.IO.Path]::IsPathRooted($entryPath) -or
            $entryPath -match '^[A-Za-z]:' -or
            $entryPath.IndexOf('\') -ge 0 -or
            $segments -contains '' -or
            $segments -contains '.' -or
            $segments -contains '..') {
            throw "Package '$($package.Name)' contains an unsafe package entry path '$entryPath'."
        }
        if (-not $archivePathMap.TryAdd($entryPath, $entry)) {
            throw "Package '$($package.Name)' contains a duplicate entry path or case-colliding path '$entryPath'."
        }
        $normalizedEntryPath = $entryPath.Normalize([Text.NormalizationForm]::FormC)
        if ($entryPath -cne $normalizedEntryPath -or
            -not $archiveNormalizedPathMap.TryAdd($normalizedEntryPath, $entryPath)) {
            throw "Package '$($package.Name)' contains a Unicode-normalization or NFC-colliding package entry path '$entryPath'."
        }
        $externalAttributes = ([int64]$entry.ExternalAttributes) -band 0xffffffffL
        $unixMode = ($externalAttributes -shr 16) -band 0xffff
        $unixFileType = $unixMode -band 0xf000
        $windowsAttributes = $externalAttributes -band 0xffff
        if (($windowsAttributes -band 0x0010) -ne 0 -or
            ($windowsAttributes -band 0x0400) -ne 0 -or
            ($unixFileType -ne 0 -and $unixFileType -ne 0x8000)) {
            throw "Package '$($package.Name)' contains a link, reparse point, or non-regular ZIP entry '$entryPath'."
        }
    }

    foreach ($wrapperPath in $wrapperPaths) {
        if (-not $archivePathMap.ContainsKey($wrapperPath) -or
            -not [string]::Equals($wrapperPath, $archivePathMap[$wrapperPath].FullName, [System.StringComparison]::Ordinal)) {
            throw "Package '$($package.Name)' wrapper file set differs from the canonical NuGet shape (missing or case-changed '$wrapperPath')."
        }
    }

    $coreProperties = @(
        $archivePathMap.Keys | Where-Object {
            $_ -match '^package/services/metadata/core-properties/(?:nuget|[0-9a-f]{32})\.psmdcp$'
        }
    )
    if ($coreProperties.Count -ne 1) {
        throw "Package '$($package.Name)' wrapper file set differs from the canonical NuGet shape (expected exactly one core-properties .psmdcp entry)."
    }
    $null = $wrapperPaths.Add($coreProperties[0])

    $archiveModulePaths = @($archivePathMap.Keys | Where-Object { -not $wrapperPaths.Contains($_) })
    $archiveMissing = @($proofFileMap.Keys | Where-Object { -not $archivePathMap.ContainsKey([string] $_) })
    $archiveExtra = @($archiveModulePaths | Where-Object { -not $proofFileMap.ContainsKey($_) })
    $archiveCaseChanged = @(
        $proofFileMap.Keys | Where-Object {
            $archivePathMap.ContainsKey([string] $_) -and
            -not [string]::Equals([string] $_, $archivePathMap[[string] $_].FullName, [System.StringComparison]::Ordinal)
        }
    )
    if ($archiveMissing.Count -gt 0 -or $archiveExtra.Count -gt 0 -or $archiveCaseChanged.Count -gt 0) {
        $details = @(
            $archiveMissing | ForEach-Object { "missing:$_" }
            $archiveExtra | ForEach-Object { "extra:$_" }
            $archiveCaseChanged | ForEach-Object { "case:$($_)->$($archivePathMap[[string] $_].FullName)" }
        ) -join ', '
        throw "The package module file set differs from the tested release proof ($details)."
    }

    foreach ($relativePath in $proofFileMap.Keys) {
        $stream = $archivePathMap[$relativePath].Open()
        try {
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try {
                $archiveHash = [System.BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
            }
            finally {
                $sha.Dispose()
            }
        }
        finally {
            $stream.Dispose()
        }
        if ($archiveHash -cne $proofFileMap[$relativePath]) {
            throw "'$relativePath' in '$($package.Name)' does not match the tested release proof."
        }
    }

    $reader = [System.IO.StreamReader]::new($archivePathMap["$moduleName.nuspec"].Open())
    try {
        [xml] $nuspec = $reader.ReadToEnd()
    }
    finally {
        $reader.Dispose()
    }
    $namespace = [System.Xml.XmlNamespaceManager]::new($nuspec.NameTable)
    $namespace.AddNamespace('n', [string] $nuspec.DocumentElement.NamespaceURI)
    $metadataNode = $nuspec.SelectSingleNode('/n:package/n:metadata', $namespace)
    if ($null -eq $metadataNode) {
        throw "Package '$($package.Name)' has no canonical nuspec metadata node."
    }
    $requiredMetadataNames = @(
        'id',
        'version',
        'authors',
        'owners',
        'requireLicenseAcceptance',
        'licenseUrl',
        'description',
        'releaseNotes',
        'copyright',
        'tags'
    )
    $supportedMetadataNames = @($requiredMetadataNames) + 'dependencies'
    $declaredRequiredModules = [object[]]::new(0)
    if ($builtManifest.ContainsKey('RequiredModules') -and $null -ne $builtManifest['RequiredModules']) {
        $declaredRequiredModules = [object[]] @($builtManifest['RequiredModules'])
    }
    $dependenciesRequired = $declaredRequiredModules.Count -gt 0
    $metadataNameSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    if ($metadataNode.Attributes.Count -ne 0) {
        throw 'Package nuspec contains unsupported nuspec metadata attributes.'
    }
    foreach ($metadataChild in @($metadataNode.ChildNodes | Where-Object NodeType -EQ ([System.Xml.XmlNodeType]::Element))) {
        if ($metadataChild.NamespaceURI -cne $nuspec.DocumentElement.NamespaceURI -or
            $metadataChild.LocalName -notin $supportedMetadataNames -or
            -not $metadataNameSet.Add($metadataChild.LocalName)) {
            throw "Package nuspec contains an unsupported nuspec metadata field '$($metadataChild.LocalName)' or duplicate field."
        }
    }
    $missingRequiredMetadata = @(
        $requiredMetadataNames | Where-Object { -not $metadataNameSet.Contains($_) })
    if ($missingRequiredMetadata.Count -ne 0 -or
        ($dependenciesRequired -and -not $metadataNameSet.Contains('dependencies')) -or
        $metadataNameSet.Count -gt $supportedMetadataNames.Count) {
        throw 'Package nuspec does not contain the exact supported nuspec metadata field set.'
    }
    function Get-NuspecMetadataValue {
        param([Parameter(Mandatory)] [string] $Name)
        $nodes = @($metadataNode.SelectNodes("n:$Name", $namespace))
        if ($nodes.Count -ne 1) {
            throw "Package nuspec must contain exactly one '$Name' metadata field."
        }
        return [string] $nodes[0].InnerText
    }
    function ConvertTo-CanonicalLineEndings {
        param([AllowEmptyString()] [string] $Value)
        return $Value.Replace("`r`n", "`n").Replace("`r", "`n")
    }

    $psData = $builtManifest.PrivateData.PSData
    $exportedFunctions = @($builtManifest.FunctionsToExport | ForEach-Object { [string] $_ })
    $expectedTags = [System.Collections.Generic.List[string]]::new()
    foreach ($tag in @($psData.Tags)) { $expectedTags.Add([string] $tag) }
    $expectedTags.Add('PSModule')
    if ($exportedFunctions.Count -gt 0) {
        $expectedTags.Add('PSIncludes_Function')
        foreach ($functionName in $exportedFunctions) { $expectedTags.Add("PSFunction_$functionName") }
        foreach ($functionName in $exportedFunctions) { $expectedTags.Add("PSCommand_$functionName") }
    }

    $expectedMetadata = [ordered] @{
        id = $moduleName
        version = $moduleVersion
        authors = [string] $builtManifest.Author
        owners = [string] $builtManifest.Author
        requireLicenseAcceptance = 'false'
        licenseUrl = [string] $psData.LicenseUri
        description = [string] $builtManifest.Description
        releaseNotes = [string] $psData.ReleaseNotes
        copyright = [string] $builtManifest.Copyright
        tags = $expectedTags -join ' '
    }

    # Publish-Module writes PowerShellGet's export-discovery tags.  The R8
    # package task deliberately uses PSResourceGet's SemVer-capable archive
    # writer instead, which retains only the manifest-declared tags.  Both
    # forms are deterministic projections of the same proven manifest; accept
    # only either exact projection so metadata tampering remains detectable.
    $expectedPsResourceTags = (@('PSModule') + @($psData.Tags) -join ' ')
    foreach ($fieldName in $expectedMetadata.Keys) {
        $actualValue = Get-NuspecMetadataValue -Name $fieldName
        $expectedValue = [string] $expectedMetadata[$fieldName]
        if ($fieldName -eq 'tags') {
            $actualValue = (@($actualValue -split '\s+' | Where-Object { $_ }) -join ' ')
            if ($actualValue -cnotin @($expectedValue, $expectedPsResourceTags)) {
                throw "Package metadata field '$fieldName' does not match the proven built manifest."
            }
            continue
        }
        else {
            $actualValue = ConvertTo-CanonicalLineEndings -Value $actualValue
            $expectedValue = ConvertTo-CanonicalLineEndings -Value $expectedValue
            if ($fieldName -eq 'releaseNotes') {
                $terminalLineEndings = [char[]] @("`r", "`n")
                $actualValue = $actualValue.TrimEnd($terminalLineEndings)
                $expectedValue = $expectedValue.TrimEnd($terminalLineEndings)
            }
        }
        if ($actualValue -cne $expectedValue) {
            throw "Package metadata field '$fieldName' does not match the proven built manifest."
        }
    }

    $expectedDependencies = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($requiredModule in $declaredRequiredModules) {
        $requiredIsDictionary = $requiredModule -is [System.Collections.IDictionary]
        $requiredName = if ($requiredModule -is [string]) {
            [string] $requiredModule
        }
        elseif ($requiredIsDictionary) {
            [string] $requiredModule['ModuleName']
        }
        else {
            [string] $requiredModule.ModuleName
        }
        $requiredPropertyNames = if ($requiredModule -is [string]) {
            @()
        }
        elseif ($requiredIsDictionary) {
            @($requiredModule.Keys)
        }
        else {
            @($requiredModule.PSObject.Properties.Name)
        }
        $requiredVersion = if ($requiredModule -is [string]) {
            ''
        }
        elseif ('RequiredVersion' -in $requiredPropertyNames -and -not [string]::IsNullOrWhiteSpace(
            $(if ($requiredIsDictionary) { [string] $requiredModule['RequiredVersion'] } else { [string] $requiredModule.RequiredVersion })
        )) {
            if ($requiredIsDictionary) { [string] $requiredModule['RequiredVersion'] } else { [string] $requiredModule.RequiredVersion }
        }
        elseif ('ModuleVersion' -in $requiredPropertyNames) {
            if ($requiredIsDictionary) { [string] $requiredModule['ModuleVersion'] } else { [string] $requiredModule.ModuleVersion }
        }
        else { '' }
        if ([string]::IsNullOrWhiteSpace($requiredName) -or [string]::IsNullOrWhiteSpace($requiredVersion) -or
            -not $expectedDependencies.TryAdd($requiredName, $requiredVersion)) {
            throw 'The built manifest RequiredModules shape cannot be represented as one exact nuspec dependency set.'
        }
    }

    $dependencyContainers = @($metadataNode.SelectNodes('n:dependencies', $namespace))
    if (($expectedDependencies.Count -gt 0 -and $dependencyContainers.Count -ne 1) -or
        ($expectedDependencies.Count -eq 0 -and $dependencyContainers.Count -gt 1)) {
        throw 'Package nuspec must contain exactly one dependencies element matching the built manifest.'
    }
    $actualDependencies = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $dependencyNodes = @()
    if ($dependencyContainers.Count -eq 1) {
        $dependencyNodes = @($dependencyContainers[0].ChildNodes |
            Where-Object NodeType -EQ ([System.Xml.XmlNodeType]::Element))
    }
    foreach ($dependencyNode in $dependencyNodes) {
        $attributeNames = @($dependencyNode.Attributes | ForEach-Object Name | Sort-Object)
        if ($dependencyNode.LocalName -cne 'dependency' -or
            $dependencyNode.NamespaceURI -cne $nuspec.DocumentElement.NamespaceURI -or
            ($attributeNames -join ',') -cne 'id,version' -or
            @($dependencyNode.ChildNodes | Where-Object NodeType -EQ ([System.Xml.XmlNodeType]::Element)).Count -ne 0) {
            throw 'Package nuspec contains an unsupported dependency shape.'
        }
        $dependencyId = [string] $dependencyNode.GetAttribute('id')
        $dependencyVersion = [string] $dependencyNode.GetAttribute('version')
        if ([string]::IsNullOrWhiteSpace($dependencyId) -or [string]::IsNullOrWhiteSpace($dependencyVersion) -or
            -not $actualDependencies.TryAdd($dependencyId, $dependencyVersion)) {
            throw 'Package nuspec contains an invalid or duplicate dependency.'
        }
    }
    if ($actualDependencies.Count -ne $expectedDependencies.Count) {
        throw 'Package nuspec dependencies do not match the proven built manifest.'
    }
    foreach ($dependencyId in $expectedDependencies.Keys) {
        if (-not $actualDependencies.ContainsKey($dependencyId) -or
            $actualDependencies[$dependencyId] -cne $expectedDependencies[$dependencyId]) {
            throw 'Package nuspec dependencies do not match the proven built manifest.'
        }
    }
}
finally {
    $archive.Dispose()
}

$resultsDirectory = Join-Path $RepositoryRoot 'output/testResults'
foreach ($resultName in @($proofNUnitName, $proofPesterObjectName)) {
    if ([string]::IsNullOrWhiteSpace($resultName) -or
        $resultName.IndexOfAny([char[]] @('/', '\')) -ge 0 -or
        [System.IO.Path]::GetFileName($resultName) -cne $resultName) {
        throw "The tested release proof contains an unsafe result filename '$resultName'."
    }
}
$nunitMatch = [regex]::Match($proofNUnitName, '^NUnitXml_(?<suffix>.+\.xml)$')
$pesterObjectMatch = [regex]::Match($proofPesterObjectName, '^PesterObject_(?<suffix>.+\.xml)$')
if (-not $nunitMatch.Success -or
    -not $pesterObjectMatch.Success -or
    $nunitMatch.Groups['suffix'].Value -cne $pesterObjectMatch.Groups['suffix'].Value) {
    throw 'The tested release proof does not bind one matching NUnit/Pester-object result pair.'
}
if ($proofNUnitHash -notmatch '^[0-9a-fA-F]{64}$' -or
    $proofPesterObjectHash -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'The tested release proof contains an invalid NUnit or Pester-object hash.'
}
$proofNUnitHash = $proofNUnitHash.ToLowerInvariant()
$proofPesterObjectHash = $proofPesterObjectHash.ToLowerInvariant()

$boundNUnitPath = Join-Path $resultsDirectory $proofNUnitName
$boundPesterObjectPath = Join-Path $resultsDirectory $proofPesterObjectName
if (-not (Test-Path -LiteralPath $boundNUnitPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $boundPesterObjectPath -PathType Leaf)) {
    throw 'A result file bound by the tested release proof is missing.'
}
if (-not [string]::IsNullOrWhiteSpace($TestResultPath)) {
    $suppliedResultPath = (Resolve-Path -LiteralPath $TestResultPath).ProviderPath
    $resolvedBoundNUnitPath = (Resolve-Path -LiteralPath $boundNUnitPath).ProviderPath
    $comparison = if ($IsWindows) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
    if (-not [string]::Equals($suppliedResultPath, $resolvedBoundNUnitPath, $comparison)) {
        throw "The supplied NUnit result is not the one bound by the tested release proof. Use '$boundNUnitPath'."
    }
}

function Assert-BoundFileHash {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $ExpectedHash,
        [Parameter(Mandatory)] [string] $Label
    )
    $actualHash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -cne $ExpectedHash) {
        throw "The $Label bound by the tested release proof changed after proof creation."
    }
}
Assert-BoundFileHash -Path $boundNUnitPath -ExpectedHash $proofNUnitHash -Label 'NUnit result'
Assert-BoundFileHash -Path $boundPesterObjectPath -ExpectedHash $proofPesterObjectHash -Label 'Pester object'

[xml] $resultDocument = Get-Content -LiteralPath $boundNUnitPath -Raw
$resultRoot = $resultDocument.SelectSingleNode('/test-results')
if ($null -eq $resultRoot) {
    throw 'The NUnit result has no <test-results> root.'
}
function Get-RequiredCount {
    param([Parameter(Mandatory)] [System.Xml.XmlElement] $Element, [Parameter(Mandatory)] [string] $Name)
    $value = [string] $Element.GetAttribute($Name)
    $parsed = 0
    if (-not [int]::TryParse($value, [ref] $parsed) -or $parsed -lt 0) {
        throw "The NUnit '$Name' count is unreadable: '$value'."
    }
    return $parsed
}
$topSuite = $resultRoot.SelectSingleNode('test-suite')
if ($null -eq $topSuite) {
    throw 'The NUnit result has no top-level test suite.'
}
$actualSummary = [ordered] @{
    overallResult = [string] $topSuite.GetAttribute('result')
    pesterResult = ''
    executed = $false
    total = Get-RequiredCount -Element $resultRoot -Name 'total'
    passed = 0
    failures = Get-RequiredCount -Element $resultRoot -Name 'failures'
    errors = Get-RequiredCount -Element $resultRoot -Name 'errors'
    skipped = Get-RequiredCount -Element $resultRoot -Name 'skipped'
    inconclusive = Get-RequiredCount -Element $resultRoot -Name 'inconclusive'
    notRun = 0
    failedBlocks = 0
    failedContainers = 0
}

$pesterResult = Import-Clixml -LiteralPath $boundPesterObjectPath
foreach ($requiredProperty in @(
    'Result',
    'TotalCount',
    'PassedCount',
    'FailedCount',
    'SkippedCount',
    'NotRunCount',
    'InconclusiveCount',
    'FailedBlocksCount',
    'FailedContainersCount',
    'Executed'
)) {
    if ($requiredProperty -notin @($pesterResult.PSObject.Properties.Name)) {
        throw "The Pester object has no '$requiredProperty' property, so the full result cannot be verified."
    }
}
function Get-RequiredPesterCount {
    param([Parameter(Mandatory)] [string] $Name)
    $raw = $pesterResult.$Name
    $parsed = 0
    if ($null -eq $raw -or -not [int]::TryParse([string] $raw, [ref] $parsed) -or $parsed -lt 0) {
        throw "The Pester '$Name' count is unreadable: '$raw'."
    }
    return $parsed
}
function Get-RequiredPesterBoolean {
    param([Parameter(Mandatory)] [string] $Name)
    $raw = $pesterResult.$Name
    $parsed = $false
    if ($null -eq $raw -or -not [bool]::TryParse([string] $raw, [ref] $parsed)) {
        throw "The Pester '$Name' value is unreadable: '$raw'."
    }
    return $parsed
}
$actualSummary.pesterResult = [string] $pesterResult.Result
$actualSummary.executed = Get-RequiredPesterBoolean -Name 'Executed'
$pesterTotal = Get-RequiredPesterCount -Name 'TotalCount'
$actualSummary.passed = Get-RequiredPesterCount -Name 'PassedCount'
$pesterFailed = Get-RequiredPesterCount -Name 'FailedCount'
$pesterSkipped = Get-RequiredPesterCount -Name 'SkippedCount'
$actualSummary.notRun = Get-RequiredPesterCount -Name 'NotRunCount'
$pesterInconclusive = Get-RequiredPesterCount -Name 'InconclusiveCount'
$actualSummary.failedBlocks = Get-RequiredPesterCount -Name 'FailedBlocksCount'
$actualSummary.failedContainers = Get-RequiredPesterCount -Name 'FailedContainersCount'
if ($actualSummary.failedBlocks -gt 0) {
    throw "$($actualSummary.failedBlocks) failed block(s) were recorded in the bound Pester result."
}
if ($actualSummary.failedContainers -gt 0) {
    throw "$($actualSummary.failedContainers) failed container(s) / discovery error(s) were recorded in the bound Pester result."
}
if (-not $actualSummary.executed) {
    throw 'The bound Pester result was not executed.'
}
if ($actualSummary.inconclusive -gt 0 -or $pesterInconclusive -gt 0) {
    throw "$([Math]::Max($actualSummary.inconclusive, $pesterInconclusive)) inconclusive test(s) were recorded in the bound result."
}
if ($pesterTotal -ne $actualSummary.total -or
    $pesterFailed -ne $actualSummary.failures -or
    $pesterSkipped -ne $actualSummary.skipped -or
    $pesterInconclusive -ne $actualSummary.inconclusive) {
    throw 'The bound NUnit and Pester-object result summaries disagree.'
}
$pesterOutcomeTotal = [long] $actualSummary.passed +
    [long] $actualSummary.failures +
    [long] $actualSummary.skipped +
    [long] $actualSummary.inconclusive +
    [long] $actualSummary.notRun
if ($pesterOutcomeTotal -ne [long] $actualSummary.total) {
    throw "Pester count arithmetic is inconsistent: passed + failed + skipped + inconclusive + NotRun is $pesterOutcomeTotal, not total $($actualSummary.total)."
}

foreach ($summaryField in $actualSummary.Keys) {
    $proofValue = if ($summaryField -in @('overallResult', 'pesterResult')) {
        [string] $proofSummary.$summaryField
    }
    elseif ($summaryField -eq 'executed') {
        [bool] $proofSummary.$summaryField
    }
    else {
        [int] $proofSummary.$summaryField
    }
    if ($proofValue -cne $actualSummary[$summaryField]) {
        throw "The tested release proof summary does not match the bound result for '$summaryField'."
    }
}

$gatePath = Join-Path $RepositoryRoot 'tests/QA/Assert-GateResult.ps1'
if (-not (Test-Path -LiteralPath $gatePath -PathType Leaf)) {
    throw "The whole-result gate is missing at '$gatePath'."
}
$gateOutput = & pwsh -NoLogo -NoProfile -File $gatePath `
    -ResultPath $boundNUnitPath `
    -MinimumTests $minimumTests `
    -AllowedSkips $allowedSkips 2>&1
$gateExitCode = $LASTEXITCODE
if ($gateExitCode -ne 0) {
    $flatGateOutput = (($gateOutput | Out-String) -replace '\r?\n\s*\|\s*', ' ' -replace '\s+', ' ').Trim()
    throw "The result bound by the tested release proof did not pass the whole-result gate: $flatGateOutput"
}
if ($actualSummary.pesterResult -cne 'Passed') {
    throw "The bound Pester result is '$($actualSummary.pesterResult)', not Passed."
}
if ($actualSummary.notRun -gt $allowedNotRun) {
    throw "$($actualSummary.notRun) NotRun test block(s) exceed the tested release allowance of $allowedNotRun."
}

# Recheck the result bytes after parsing and gating so a concurrent replacement cannot be
# accepted as one byte sequence and retained as another.
Assert-BoundFileHash -Path $boundNUnitPath -ExpectedHash $proofNUnitHash -Label 'NUnit result'
Assert-BoundFileHash -Path $boundPesterObjectPath -ExpectedHash $proofPesterObjectHash -Label 'Pester object'

$finalProofHash = (Get-FileHash -LiteralPath $ProofPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($finalProofHash -cne $initialProofHash) {
    throw 'The tested release proof changed while it was being verified.'
}
$finalPackageHash = (Get-FileHash -LiteralPath $package.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
if ($finalPackageHash -cne $proofPackageHash) {
    throw "The '$($package.Name)' package archive changed while it was being verified."
}

# Recheck the built payload after the external whole-result gate. The package snapshot is
# the publication input, but this second pass also keeps the proof's claim about the built
# module true at the instant verification completes.
[string[]] $finalBuiltPaths = @(
    Get-ChildItem -LiteralPath $builtModuleDirectory -Recurse -File -Force |
        ForEach-Object { $_.FullName.Substring($builtModuleDirectory.Length + 1) -replace '\\', '/' }
)
if ($finalBuiltPaths.Count -ne $proofFileMap.Count) {
    throw 'The built module file set changed while the tested release proof was being verified.'
}
foreach ($relativePath in $finalBuiltPaths) {
    if (-not $proofFileMap.ContainsKey($relativePath) -or
        -not [string]::Equals($relativePath, $currentPathMap[$relativePath], [System.StringComparison]::Ordinal)) {
        throw 'The built module file set changed while the tested release proof was being verified.'
    }
    $finalBuiltHash = (Get-FileHash -LiteralPath (Join-Path $builtModuleDirectory $relativePath) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($finalBuiltHash -cne $proofFileMap[$relativePath]) {
        throw "'$relativePath' in the built module changed while the tested release proof was being verified."
    }
}

function Copy-VerifiedReleaseFile {
    param(
        [Parameter(Mandatory)] [string] $SourcePath,
        [Parameter(Mandatory)] [string] $DestinationPath,
        [Parameter(Mandatory)] [string] $ExpectedHash,
        [Parameter(Mandatory)] [string] $Label
    )

    $sourceFullPath = (Resolve-Path -LiteralPath $SourcePath).ProviderPath
    $destinationFullPath = [System.IO.Path]::GetFullPath($DestinationPath)
    $comparison = if ($IsWindows) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
    if ([string]::Equals($sourceFullPath, $destinationFullPath, $comparison)) {
        throw "The verified $Label snapshot destination must differ from its source path."
    }
    if (Test-Path -LiteralPath $destinationFullPath) {
        throw "The verified $Label snapshot destination '$destinationFullPath' already exists."
    }
    $destinationDirectory = Split-Path $destinationFullPath -Parent
    if (-not (Test-Path -LiteralPath $destinationDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
    }
    try {
        [System.IO.File]::Copy($sourceFullPath, $destinationFullPath, $false)
        $snapshotHash = (Get-FileHash -LiteralPath $destinationFullPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($snapshotHash -cne $ExpectedHash) {
            throw "The verified $Label snapshot does not match the bytes that passed verification."
        }
    }
    catch {
        Remove-Item -LiteralPath $destinationFullPath -Force -ErrorAction SilentlyContinue
        throw
    }
    return $destinationFullPath
}

$verifiedPackagePath = $null
if (-not [string]::IsNullOrWhiteSpace($VerifiedPackageCopyPath)) {
    $verifiedPackagePath = Copy-VerifiedReleaseFile `
        -SourcePath $package.FullName `
        -DestinationPath $VerifiedPackageCopyPath `
        -ExpectedHash $proofPackageHash `
        -Label 'package'
}
$verifiedProofPath = $null
if (-not [string]::IsNullOrWhiteSpace($VerifiedProofCopyPath)) {
    $verifiedProofPath = Copy-VerifiedReleaseFile `
        -SourcePath $ProofPath `
        -DestinationPath $VerifiedProofCopyPath `
        -ExpectedHash $initialProofHash `
        -Label 'proof'
}

Write-Host "VERIFIED TESTED RELEASE: $moduleName $moduleVersion; $($proofFileMap.Count) shipped file(s); package sha256 $proofPackageHash; $($actualSummary.total) tests; 0 failed; 0 errors; 0 skipped; 0 NotRun."

[pscustomobject] [ordered] @{
    ModuleName = $moduleName
    Version = $moduleVersion
    BaseVersion = $proofModuleBaseVersion
    PackageName = $package.Name
    PackageSha256 = $proofPackageHash
    ProofSha256 = $initialProofHash
    RunId = $proofRunId
    ShippedFileCount = $proofFileMap.Count
    TestCount = $actualSummary.total
    ProofPath = (Resolve-Path -LiteralPath $ProofPath).ProviderPath
    NUnitResultPath = (Resolve-Path -LiteralPath $boundNUnitPath).ProviderPath
    PesterObjectPath = (Resolve-Path -LiteralPath $boundPesterObjectPath).ProviderPath
    VerifiedPackagePath = $verifiedPackagePath
    VerifiedProofPath = $verifiedProofPath
}
