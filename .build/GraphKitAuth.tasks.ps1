param([switch] $SkipTaskRegistration)

$script:GraphKitAuthPayloadFiles = @(
    'GraphKit.Auth.Contracts.dll'
    'GraphKit.Auth.dll'
    'GraphKit.Auth.deps.json'
    'Microsoft.Identity.Client.dll'
    'Microsoft.IdentityModel.Abstractions.dll'
)
$script:GraphKitAuthProviderFiles = @(
    'GraphKit.Auth.dll'
    'GraphKit.Auth.deps.json'
    'Microsoft.Identity.Client.dll'
    'Microsoft.IdentityModel.Abstractions.dll'
)
$script:GraphKitAuthStage = $null
$script:GraphKitAuthStageCaptureType = $null
$script:GraphKitAuthAbiFixtureState = $null
$script:GraphKitAuthAbiGitConfigState = $null
$script:GraphKitAuthExpectedTestCount = 77

function Assert-GraphKitAuthTestResult {
    [CmdletBinding()]
    param([Parameter(Mandatory)][xml] $Result)

    $outcomes = @($Result.TestRun.Results.UnitTestResult | ForEach-Object { [string]$_.outcome })
    $counters = $Result.TestRun.ResultSummary.Counters
    $zeroCounterNames = @('failed','error','timeout','aborted','inconclusive','notExecuted',
        'notRunnable','disconnected','warning','inProgress','pending')
    $nonZeroCounters = @($zeroCounterNames | Where-Object { [int]$counters.$_ -ne 0 })
    if ($outcomes.Count -ne $script:GraphKitAuthExpectedTestCount -or
        @($outcomes | Where-Object { $_ -cne 'Passed' }).Count -ne 0 -or
        [int]$counters.total -ne $outcomes.Count -or [int]$counters.executed -ne $outcomes.Count -or
        [int]$counters.passed -ne $outcomes.Count -or $nonZeroCounters.Count -ne 0) {
        throw "GraphKit.Auth machine-readable test result is incomplete: expected exactly $($script:GraphKitAuthExpectedTestCount); total=$($outcomes.Count), passed=$(@($outcomes | Where-Object { $_ -ceq 'Passed' }).Count)."
    }
}

function Initialize-GraphKitAuthStageCapture {
    if ($null -ne $script:GraphKitAuthStageCaptureType) { return }
    $root = Split-Path $PSScriptRoot -Parent
    $helperPath = Join-Path $root 'scripts/private/GraphKit.AuthStageCapture.cs'
    if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf)) {
        throw "The private GraphKit.Auth stage-capture helper is missing at '$helperPath'."
    }
    $helperBytes = [IO.File]::ReadAllBytes($helperPath)
    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    try { $template = $strictUtf8.GetString($helperBytes) }
    catch { throw "The private GraphKit.Auth capture helper is not strict UTF-8." }
    $marker = '__GRAPHKIT_AUTH_STAGE_CAPTURE_NAMESPACE__'
    if (($template.Split([string[]]@($marker), [StringSplitOptions]::None).Length - 1) -ne 1) {
        throw 'The private GraphKit.Auth capture helper must contain exactly one namespace marker.'
    }
    $helperHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($helperBytes)).ToLowerInvariant()
    $nonce = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(16)).ToLowerInvariant()
    $namespace = "GraphKit.R8.StageCapture.H$helperHash.N$nonce"
    $expectedTypeName = "$namespace.GraphKitAuthStageCapture"
    if (@([AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object { $_.GetType($expectedTypeName, $false, $false) } | Where-Object { $null -ne $_ }).Count) {
        throw "The generated GraphKit.Auth capture type '$expectedTypeName' already exists."
    }
    $compiled = @(Add-Type -TypeDefinition $template.Replace($marker, $namespace) -PassThru -ErrorAction Stop)
    $compiledMatches = @($compiled | Where-Object FullName -CEQ $expectedTypeName)
    $loaded = @([AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object { $_.GetType($expectedTypeName, $false, $false) } | Where-Object { $null -ne $_ })
    if ($compiledMatches.Count -ne 1 -or $loaded.Count -ne 1 -or -not [object]::ReferenceEquals($compiledMatches[0], $loaded[0])) {
        throw 'The proof-bound GraphKit.Auth capture helper collided during compilation.'
    }
    $script:GraphKitAuthStageCaptureType = $compiledMatches[0]
}

function Get-GraphKitAuthOutputRoot {
    param([Parameter(Mandatory)][string] $OutputRoot)
    $resolved = [IO.Path]::GetFullPath($OutputRoot)
    if ([IO.Path]::GetFileName($resolved) -ceq 'GraphKit.Auth') { return $resolved }
    return Join-Path $resolved 'GraphKit.Auth'
}

function Get-GraphKitAuthPortableChildEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $ParentPath,
        [Parameter(Mandatory)][string] $ChildName,
        [Parameter(Mandatory)][string] $Kind
    )
    Assert-GraphKitAuthSafeSegment -Value $ChildName -Kind $Kind
    $parent = [IO.Path]::GetFullPath($ParentPath)
    $expectedNfc = $ChildName.Normalize([Text.NormalizationForm]::FormC)
    $portableMatches = @([IO.Directory]::EnumerateFileSystemEntries($parent) | Where-Object {
        $actualName = [IO.Path]::GetFileName($_)
        [string]::Equals(
            $actualName.Normalize([Text.NormalizationForm]::FormC),
            $expectedNfc,
            [StringComparison]::OrdinalIgnoreCase)
    })
    if ($portableMatches.Count -gt 1) {
        throw "The GraphKit.Auth $Kind has multiple entries for the portable name '$ChildName'."
    }
    if ($portableMatches.Count -eq 1) {
        $actualName = [IO.Path]::GetFileName($portableMatches[0])
        if ($actualName -cne $ChildName) {
            throw "The GraphKit.Auth $Kind '$actualName' is a portable alias for '$ChildName'."
        }
        return [pscustomobject]@{
            Exists = $true
            Path = [string]$portableMatches[0]
            Name = $actualName
        }
    }
    return [pscustomobject]@{ Exists = $false; Path = $null; Name = $null }
}

function Remove-GraphKitAuthVerifiedEmptyDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $ParentPath,
        [Parameter(Mandatory)] $ParentEvidence,
        [Parameter(Mandatory)][string] $ChildName,
        [Parameter(Mandatory)] $ChildEvidence,
        [Parameter(Mandatory)][string] $Kind
    )
    $parent = [IO.Path]::GetFullPath($ParentPath)
    $parentParent = Split-Path $parent -Parent
    $parentName = [IO.Path]::GetFileName($parent)
    $reopenedParent = $script:GraphKitAuthStageCaptureType::InspectDirectory(
        $parentParent, $parentName)
    if ([string]$reopenedParent.NativeIdentity -cne [string]$ParentEvidence.NativeIdentity -or
        [string]$reopenedParent.PhysicalPath -cne [string]$ParentEvidence.PhysicalPath) {
        throw "The GraphKit.Auth $Kind parent changed; ambiguous cleanup was refused."
    }
    $entry = Get-GraphKitAuthPortableChildEntry -ParentPath $parent `
        -ChildName $ChildName -Kind $Kind
    if (-not $entry.Exists) {
        throw "The GraphKit.Auth $Kind disappeared; ambiguous cleanup was refused."
    }
    $current = $script:GraphKitAuthStageCaptureType::InspectDirectory($parent, $ChildName)
    if ([string]$current.NativeIdentity -cne [string]$ChildEvidence.NativeIdentity -or
        [string]$current.PhysicalPath -cne [string]$ChildEvidence.PhysicalPath -or
        -not (Test-GraphKitAuthContainedPhysicalPath $reopenedParent.PhysicalPath $current.PhysicalPath) -or
        @([IO.Directory]::EnumerateFileSystemEntries($entry.Path)).Count -ne 0) {
        throw "The GraphKit.Auth $Kind is not the identity-bound empty directory; ambiguous cleanup was refused."
    }
    $script:GraphKitAuthStageCaptureType::SetOwnerOnly($entry.Path, $true, $true)
    $reopened = $script:GraphKitAuthStageCaptureType::InspectDirectory($parent, $ChildName)
    if ([string]$reopened.NativeIdentity -cne [string]$ChildEvidence.NativeIdentity -or
        [string]$reopened.PhysicalPath -cne [string]$ChildEvidence.PhysicalPath -or
        @([IO.Directory]::EnumerateFileSystemEntries($entry.Path)).Count -ne 0) {
        throw "The GraphKit.Auth $Kind changed while cleanup access was applied; ambiguous cleanup was refused."
    }
    Remove-Item -LiteralPath $entry.Path -Force -ErrorAction Stop
}

function Initialize-GraphKitAuthOwnerDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $ParentPath,
        [Parameter(Mandatory)] $ParentEvidence,
        [Parameter(Mandatory)][string] $ChildName,
        [Parameter(Mandatory)][string] $Kind,
        [scriptblock] $AfterChildInspection
    )
    Initialize-GraphKitAuthStageCapture
    Assert-GraphKitAuthSafeSegment -Value $ChildName -Kind $Kind
    $parent = [IO.Path]::GetFullPath($ParentPath)
    $parentParent = Split-Path $parent -Parent
    $parentName = [IO.Path]::GetFileName($parent)
    $reopenedParent = $script:GraphKitAuthStageCaptureType::InspectDirectory($parentParent, $parentName)
    if ([string]$reopenedParent.NativeIdentity -cne [string]$ParentEvidence.NativeIdentity -or
        [string]$reopenedParent.PhysicalPath -cne [string]$ParentEvidence.PhysicalPath) {
        throw "The GraphKit.Auth $Kind parent changed before child creation."
    }
    $child = Join-Path $parent $ChildName
    $created = $false
    $reusedAtomicCollision = $false
    $before = $null
    try {
        $entry = Get-GraphKitAuthPortableChildEntry -ParentPath $parent `
            -ChildName $ChildName -Kind $Kind
        if (-not $entry.Exists) {
            try {
                $before = $script:GraphKitAuthStageCaptureType::CreateDirectoryOwnerOnly(
                    $parent, $ChildName)
                $created = $true
            }
            catch {
                if ($_.Exception.Message -notmatch 'Atomic owner-only directory destination collision') {
                    throw
                }
                $entryAfterCollision = Get-GraphKitAuthPortableChildEntry -ParentPath $parent `
                    -ChildName $ChildName -Kind $Kind
                if (-not $entryAfterCollision.Exists) { throw }
                $before = $script:GraphKitAuthStageCaptureType::InspectDirectory($parent, $ChildName)
                if (-not $script:GraphKitAuthStageCaptureType::HasInitialOwnerOnlyDirectoryAccess($before)) {
                    throw "The GraphKit.Auth $Kind collision did not resolve to an exact current-owner-only writable directory."
                }
                $reusedAtomicCollision = $true
            }
        }
        $entry = Get-GraphKitAuthPortableChildEntry -ParentPath $parent `
            -ChildName $ChildName -Kind $Kind
        if (-not $entry.Exists) {
            throw "The GraphKit.Auth $Kind path was not created."
        }
        if ($null -eq $before) {
            $before = $script:GraphKitAuthStageCaptureType::InspectDirectory($parent, $ChildName)
        }
        if (-not (Test-GraphKitAuthContainedPhysicalPath $reopenedParent.PhysicalPath $before.PhysicalPath)) {
            throw "The GraphKit.Auth $Kind path is not one physically contained no-follow directory."
        }
        if ($created -and
            -not $script:GraphKitAuthStageCaptureType::HasInitialOwnerOnlyDirectoryAccess($before)) {
            throw "The GraphKit.Auth $Kind did not begin with exact current-owner-only writable access."
        }
        if ($created -and $null -ne $AfterChildInspection) {
            & $AfterChildInspection $Kind $child $before
        }
        if (-not $created -and -not $reusedAtomicCollision) {
            if (-not $script:GraphKitAuthStageCaptureType::HasInitialOwnerOnlyDirectoryAccess($before)) {
                throw "The GraphKit.Auth $Kind is not exact current-owner-only writable before reuse."
            }
        }
        $after = $script:GraphKitAuthStageCaptureType::InspectDirectory($parent, $ChildName)
        if ([string]$after.NativeIdentity -cne [string]$before.NativeIdentity -or
            [string]$after.PhysicalPath -cne [string]$before.PhysicalPath -or
            -not (Test-GraphKitAuthContainedPhysicalPath $reopenedParent.PhysicalPath $after.PhysicalPath) -or
            -not $script:GraphKitAuthStageCaptureType::HasInitialOwnerOnlyDirectoryAccess($after)) {
            throw "The GraphKit.Auth $Kind path changed while owner-only access was applied."
        }
        return $after
    }
    catch {
        $primary = $_
        if ($created -and $null -ne $before) {
            try {
                Remove-GraphKitAuthVerifiedEmptyDirectory -ParentPath $parent `
                    -ParentEvidence $reopenedParent -ChildName $ChildName `
                    -ChildEvidence $before -Kind $Kind
            }
            catch {
                throw "GraphKit.Auth $Kind initialization failed and ambiguous cleanup was refused: $($_.Exception.Message) Original failure: $($primary.Exception.Message)"
            }
        }
        throw $primary
    }
}

function Initialize-GraphKitAuthBuildAuthorityRoot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $OutputRoot,
        [scriptblock] $AfterChildInspection
    )
    Initialize-GraphKitAuthStageCapture
    $output = [IO.Path]::GetFullPath($OutputRoot)
    if (-not (Test-Path -LiteralPath $output -PathType Container)) {
        $null = [IO.Directory]::CreateDirectory($output)
    }
    $outputParent = Split-Path $output -Parent
    $outputName = [IO.Path]::GetFileName($output)
    $outputEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory(
        $outputParent, $outputName)
    $authEntryBefore = Get-GraphKitAuthPortableChildEntry -ParentPath $output `
        -ChildName 'GraphKit.Auth' -Kind 'build auth root'
    $authCreated = -not $authEntryBefore.Exists
    $authEvidence = Initialize-GraphKitAuthOwnerDirectory -ParentPath $output `
        -ParentEvidence $outputEvidence -ChildName 'GraphKit.Auth' `
        -Kind 'build auth root' -AfterChildInspection $AfterChildInspection
    $authRoot = Join-Path $output 'GraphKit.Auth'
    try {
        $null = Initialize-GraphKitAuthOwnerDirectory -ParentPath $authRoot `
            -ParentEvidence $authEvidence -ChildName 'capture' `
            -Kind 'build capture root' -AfterChildInspection $AfterChildInspection
        return $authEvidence
    }
    catch {
        $primary = $_
        if ($authCreated) {
            try {
                Remove-GraphKitAuthVerifiedEmptyDirectory -ParentPath $output `
                    -ParentEvidence $outputEvidence -ChildName 'GraphKit.Auth' `
                    -ChildEvidence $authEvidence -Kind 'incomplete build authority root cleanup'
            }
            catch {
                throw "GraphKit.Auth build authority initialization failed and ambiguous cleanup was refused: $($_.Exception.Message) Original failure: $($primary.Exception.Message)"
            }
        }
        throw $primary
    }
}

function Remove-GraphKitAuthVerifiedInstallCandidate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $StageRoot,
        [Parameter(Mandatory)][string] $InstallName,
        [Parameter(Mandatory)] $InstallEvidence,
        [Parameter(Mandatory)][string] $FullVersion,
        [Parameter(Mandatory)] $TemporaryVersionEvidence,
        [Parameter(Mandatory)][string] $CandidateStagePath
    )
    $installPath = Join-Path $StageRoot $InstallName
    $temporaryVersion = Join-Path $installPath $FullVersion
    $currentInstall = $script:GraphKitAuthStageCaptureType::InspectDirectory($StageRoot, $InstallName)
    if ([string]$currentInstall.NativeIdentity -cne [string]$InstallEvidence.NativeIdentity -or
        [string]$currentInstall.PhysicalPath -cne [string]$InstallEvidence.PhysicalPath) {
        throw 'The GraphKit.Auth losing install candidate changed identity; ambiguous cleanup was refused.'
    }
    $currentVersion = $script:GraphKitAuthStageCaptureType::InspectDirectory(
        $installPath, $FullVersion)
    if ([string]$currentVersion.NativeIdentity -cne [string]$TemporaryVersionEvidence.NativeIdentity -or
        [string]$currentVersion.PhysicalPath -cne [string]$TemporaryVersionEvidence.PhysicalPath -or
        -not (Test-GraphKitAuthContainedPhysicalPath $currentInstall.PhysicalPath $currentVersion.PhysicalPath)) {
        throw 'The GraphKit.Auth temporary version wrapper changed identity; ambiguous cleanup was refused.'
    }
    Assert-GraphKitAuthExactDirectoryClosure -Directory $installPath `
        -ExpectedNames @($FullVersion) -Kind 'losing install root'
    $digestName = [IO.Path]::GetFileName($CandidateStagePath)
    if ($digestName -cnotmatch '^[0-9a-f]{64}$' -or
        [IO.Path]::GetFullPath($CandidateStagePath) -cne [IO.Path]::GetFullPath((Join-Path $temporaryVersion $digestName))) {
        throw 'The GraphKit.Auth candidate path is not the exact digest child of its temporary version wrapper.'
    }
    Assert-GraphKitAuthExactDirectoryClosure -Directory $temporaryVersion `
        -ExpectedNames @($digestName) -Kind 'temporary version wrapper'
    $verified = Test-GraphKitAuthSealedStage -StagePath $CandidateStagePath -FullVersion $FullVersion
    $candidateEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory(
        $temporaryVersion, $digestName)
    $payloadEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory(
        $verified.StagePath, 'payload')
    $manifestEvidence = $script:GraphKitAuthStageCaptureType::InspectFile(
        $verified.StagePath, 'manifest.json')
    foreach ($file in @($verified.Manifest.files)) {
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly(
            (Join-Path $verified.StagePath ([string]$file.path)), $false, $true)
    }
    $script:GraphKitAuthStageCaptureType::SetOwnerOnly($verified.ManifestPath, $false, $true)
    $script:GraphKitAuthStageCaptureType::SetOwnerOnly($verified.PayloadPath, $true, $true)
    $script:GraphKitAuthStageCaptureType::SetOwnerOnly($verified.StagePath, $true, $true)
    $script:GraphKitAuthStageCaptureType::SetOwnerOnly($temporaryVersion, $true, $true)
    $script:GraphKitAuthStageCaptureType::SetOwnerOnly($installPath, $true, $true)

    $reopenedInstall = $script:GraphKitAuthStageCaptureType::InspectDirectory($StageRoot, $InstallName)
    $reopenedVersion = $script:GraphKitAuthStageCaptureType::InspectDirectory($installPath, $FullVersion)
    $reopenedCandidate = $script:GraphKitAuthStageCaptureType::InspectDirectory(
        $temporaryVersion, $digestName)
    $reopenedPayload = $script:GraphKitAuthStageCaptureType::InspectDirectory(
        $verified.StagePath, 'payload')
    $reopenedManifest = $script:GraphKitAuthStageCaptureType::InspectFile(
        $verified.StagePath, 'manifest.json')
    if ([string]$reopenedInstall.NativeIdentity -cne [string]$InstallEvidence.NativeIdentity -or
        [string]$reopenedInstall.PhysicalPath -cne [string]$InstallEvidence.PhysicalPath -or
        [string]$reopenedVersion.NativeIdentity -cne [string]$TemporaryVersionEvidence.NativeIdentity -or
        [string]$reopenedVersion.PhysicalPath -cne [string]$TemporaryVersionEvidence.PhysicalPath -or
        [string]$reopenedCandidate.NativeIdentity -cne [string]$candidateEvidence.NativeIdentity -or
        [string]$reopenedCandidate.PhysicalPath -cne [string]$candidateEvidence.PhysicalPath -or
        [string]$reopenedPayload.NativeIdentity -cne [string]$payloadEvidence.NativeIdentity -or
        [string]$reopenedPayload.PhysicalPath -cne [string]$payloadEvidence.PhysicalPath -or
        [string]$reopenedManifest.NativeIdentity -cne [string]$manifestEvidence.NativeIdentity -or
        [string]$reopenedManifest.PhysicalPath -cne [string]$manifestEvidence.PhysicalPath -or
        [string]$reopenedManifest.Sha256 -cne $digestName -or
        [long]$reopenedManifest.LinkCount -ne 1 -or
        -not (Test-GraphKitAuthContainedPhysicalPath $reopenedInstall.PhysicalPath $reopenedVersion.PhysicalPath) -or
        -not (Test-GraphKitAuthContainedPhysicalPath $reopenedVersion.PhysicalPath $reopenedCandidate.PhysicalPath) -or
        -not (Test-GraphKitAuthContainedPhysicalPath $reopenedCandidate.PhysicalPath $reopenedPayload.PhysicalPath)) {
        throw 'The GraphKit.Auth losing install candidate changed before recursive deletion; ambiguous cleanup was refused.'
    }
    Assert-GraphKitAuthExactDirectoryClosure -Directory $installPath `
        -ExpectedNames @($FullVersion) -Kind 'losing install root before deletion'
    Assert-GraphKitAuthExactDirectoryClosure -Directory $temporaryVersion `
        -ExpectedNames @($digestName) -Kind 'temporary version wrapper before deletion'
    Assert-GraphKitAuthExactDirectoryClosure -Directory $verified.StagePath `
        -ExpectedNames @('manifest.json','payload') -Kind 'losing candidate envelope before deletion'
    Assert-GraphKitAuthExactDirectoryClosure -Directory $verified.PayloadPath `
        -ExpectedNames $script:GraphKitAuthPayloadFiles -Kind 'losing candidate payload before deletion'
    foreach ($record in @($verified.Manifest.files)) {
        $actual = $script:GraphKitAuthStageCaptureType::InspectFile(
            $verified.StagePath, [string]$record.path)
        if ([string]$actual.NativeIdentity -cne [string]$record.nativeIdentity -or
            [string]$actual.Sha256 -cne [string]$record.sha256 -or
            [long]$actual.Length -ne [long]$record.length -or
            [long]$actual.LinkCount -ne 1 -or
            -not (Test-GraphKitAuthContainedPhysicalPath $reopenedPayload.PhysicalPath $actual.PhysicalPath)) {
            throw "The GraphKit.Auth losing candidate file '$($record.path)' changed before recursive deletion; ambiguous cleanup was refused."
        }
    }
    Remove-Item -LiteralPath $installPath -Recurse -Force -ErrorAction Stop
}

function Remove-GraphKitAuthVerifiedCaptureCandidate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $CaptureRoot,
        [Parameter(Mandatory)][string] $CaptureName,
        [Parameter(Mandatory)] $CaptureEvidence,
        [Parameter(Mandatory)] $PayloadEvidence,
        [Parameter(Mandatory)] $CapturedFileEvidence,
        $ManifestWrite
    )
    $capture = Join-Path $CaptureRoot $CaptureName
    $payload = Join-Path $capture 'payload'
    $currentCapture = $script:GraphKitAuthStageCaptureType::InspectDirectory(
        $CaptureRoot, $CaptureName)
    $currentPayload = $script:GraphKitAuthStageCaptureType::InspectDirectory(
        $capture, 'payload')
    if ([string]$currentCapture.NativeIdentity -cne [string]$CaptureEvidence.NativeIdentity -or
        [string]$currentCapture.PhysicalPath -cne [string]$CaptureEvidence.PhysicalPath -or
        [string]$currentPayload.NativeIdentity -cne [string]$PayloadEvidence.NativeIdentity -or
        [string]$currentPayload.PhysicalPath -cne [string]$PayloadEvidence.PhysicalPath -or
        -not (Test-GraphKitAuthContainedPhysicalPath $currentCapture.PhysicalPath $currentPayload.PhysicalPath)) {
        throw 'The GraphKit.Auth incomplete capture changed identity; ambiguous cleanup was refused.'
    }
    $expectedPayloadNames = @($CapturedFileEvidence.Keys)
    Assert-GraphKitAuthExactDirectoryClosure -Directory $payload `
        -ExpectedNames $expectedPayloadNames -Kind 'incomplete capture payload'
    foreach ($name in $expectedPayloadNames) {
        $expected = $CapturedFileEvidence[$name]
        $actual = $script:GraphKitAuthStageCaptureType::InspectFile($payload, $name)
        if ([string]$actual.NativeIdentity -cne [string]$expected.NativeIdentity -or
            [string]$actual.PhysicalPath -cne [string]$expected.PhysicalPath -or
            [string]$actual.Sha256 -cne [string]$expected.Sha256 -or
            [long]$actual.Length -ne [long]$expected.Length -or
            [long]$actual.LinkCount -ne 1 -or
            -not (Test-GraphKitAuthContainedPhysicalPath $currentPayload.PhysicalPath $actual.PhysicalPath)) {
            throw "The GraphKit.Auth incomplete capture file '$name' changed; ambiguous cleanup was refused."
        }
    }
    $expectedEnvelopeNames = [Collections.Generic.List[string]]::new()
    $expectedEnvelopeNames.Add('payload')
    if ($null -ne $ManifestWrite) { $expectedEnvelopeNames.Add('manifest.json') }
    Assert-GraphKitAuthExactDirectoryClosure -Directory $capture `
        -ExpectedNames @($expectedEnvelopeNames) -Kind 'incomplete capture envelope'
    if ($null -ne $ManifestWrite) {
        $expectedManifest = $ManifestWrite.Destination
        $actualManifest = $script:GraphKitAuthStageCaptureType::InspectFile($capture, 'manifest.json')
        if ([string]$actualManifest.NativeIdentity -cne [string]$expectedManifest.NativeIdentity -or
            [string]$actualManifest.PhysicalPath -cne [string]$expectedManifest.PhysicalPath -or
            [string]$actualManifest.Sha256 -cne [string]$expectedManifest.Sha256 -or
            [long]$actualManifest.Length -ne [long]$expectedManifest.Length -or
            [long]$actualManifest.LinkCount -ne 1) {
            throw 'The GraphKit.Auth incomplete manifest changed; ambiguous cleanup was refused.'
        }
    }
    foreach ($name in $expectedPayloadNames) {
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly(
            (Join-Path $payload $name), $false, $true)
    }
    if ($null -ne $ManifestWrite) {
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly(
            (Join-Path $capture 'manifest.json'), $false, $true)
    }
    $script:GraphKitAuthStageCaptureType::SetOwnerOnly($payload, $true, $true)
    $script:GraphKitAuthStageCaptureType::SetOwnerOnly($capture, $true, $true)
    Remove-Item -LiteralPath $capture -Recurse -Force -ErrorAction Stop
}

function Remove-GraphKitAuthVerifiedEmptyInstallCandidate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $StageRoot,
        [Parameter(Mandatory)][string] $InstallName,
        [Parameter(Mandatory)] $InstallEvidence,
        [Parameter(Mandatory)][string] $FullVersion,
        [Parameter(Mandatory)] $TemporaryVersionEvidence
    )
    $installRoot = Join-Path $StageRoot $InstallName
    $temporaryVersionRoot = Join-Path $installRoot $FullVersion
    $currentInstall = $script:GraphKitAuthStageCaptureType::InspectDirectory(
        $StageRoot, $InstallName)
    $currentVersion = $script:GraphKitAuthStageCaptureType::InspectDirectory(
        $installRoot, $FullVersion)
    if ([string]$currentInstall.NativeIdentity -cne [string]$InstallEvidence.NativeIdentity -or
        [string]$currentInstall.PhysicalPath -cne [string]$InstallEvidence.PhysicalPath -or
        [string]$currentVersion.NativeIdentity -cne [string]$TemporaryVersionEvidence.NativeIdentity -or
        [string]$currentVersion.PhysicalPath -cne [string]$TemporaryVersionEvidence.PhysicalPath -or
        @([IO.Directory]::EnumerateFileSystemEntries($temporaryVersionRoot)).Count -ne 0) {
        throw 'The GraphKit.Auth incomplete install wrapper is ambiguous.'
    }
    $script:GraphKitAuthStageCaptureType::SetOwnerOnly(
        $temporaryVersionRoot, $true, $true)
    Remove-Item -LiteralPath $temporaryVersionRoot -Force -ErrorAction Stop
    if (@([IO.Directory]::EnumerateFileSystemEntries($installRoot)).Count -ne 0) {
        throw 'The GraphKit.Auth incomplete install root became non-empty during cleanup.'
    }
    $script:GraphKitAuthStageCaptureType::SetOwnerOnly($installRoot, $true, $true)
    Remove-Item -LiteralPath $installRoot -Force -ErrorAction Stop
}

function Assert-GraphKitAuthSafeSegment {
    param([Parameter(Mandatory)][string] $Value, [Parameter(Mandatory)][string] $Kind)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -in @('.', '..') -or
        [IO.Path]::IsPathRooted($Value) -or $Value.IndexOfAny([char[]]@('/', '\')) -ge 0 -or
        -not $Value.IsNormalized([Text.NormalizationForm]::FormC)) {
        throw "The GraphKit.Auth $Kind '$Value' is not one safe NFC path segment."
    }
}

function Assert-GraphKitAuthPortableNameSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $Names,
        [Parameter(Mandatory)][string] $Kind
    )
    $portable = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $normalized = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $Names) {
        if ([string]::IsNullOrWhiteSpace($name) -or $name.IndexOf('\') -ge 0 -or
            -not $name.IsNormalized([Text.NormalizationForm]::FormC)) {
            throw "The GraphKit.Auth $Kind contains an unsafe or non-NFC name."
        }
        if (-not $portable.Add($name) -or
            -not $normalized.Add($name.Normalize([Text.NormalizationForm]::FormC))) {
            throw "The GraphKit.Auth $Kind contains a portable alias for '$name'."
        }
    }
}

function Assert-GraphKitAuthExactDirectoryClosure {
    param(
        [Parameter(Mandatory)][string] $Directory,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $ExpectedNames,
        [Parameter(Mandatory)][string] $Kind
    )
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        throw "The GraphKit.Auth $Kind directory '$Directory' is missing."
    }
    $actual = [Collections.Generic.List[string]]::new()
    foreach ($entryPath in [IO.Directory]::EnumerateFileSystemEntries($Directory)) {
        $actual.Add([IO.Path]::GetFileName($entryPath))
    }
    Assert-GraphKitAuthPortableNameSet -Names @($actual) -Kind $Kind
    $actualSorted = @($actual | Sort-Object)
    $expectedSorted = @($ExpectedNames | Sort-Object)
    if (($actualSorted -join '|') -cne ($expectedSorted -join '|')) {
        throw "The GraphKit.Auth $Kind closure is not exact. Expected '$($expectedSorted -join '|')'; found '$($actualSorted -join '|')'."
    }
}

function Test-GraphKitAuthContainedPhysicalPath {
    param([Parameter(Mandatory)][string] $Root, [Parameter(Mandatory)][string] $Candidate)
    $comparison = if ($IsWindows) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $candidatePath = [IO.Path]::GetFullPath($Candidate)
    $prefix = $rootPath + [IO.Path]::DirectorySeparatorChar
    return $candidatePath.StartsWith($prefix, $comparison)
}

function Test-GraphKitAuthSealedPermission {
    param($Evidence, [Parameter(Mandatory)][bool] $Directory)
    if ($Evidence.OwnerWritable) { return $false }
    if ($IsWindows) {
        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        return [string]$Evidence.OwnerSid -ceq $currentSid -and
            [string]$Evidence.CurrentIdentitySid -ceq $currentSid -and
            [bool]$Evidence.AccessRulesProtected -and
            -not [bool]$Evidence.HasInheritedAccessRules -and
            [bool]$Evidence.ExactOwnerOnlyAccess -and
            ($Directory -or [bool]$Evidence.FileReadOnly)
    }
    $expected = if ($Directory) { 0x140 } else { 0x100 } # 0500 / 0400
    return [int]$Evidence.UnixMode -eq $expected
}

function Test-GraphKitAuthOwnerOnlyWritableDirectory {
    param([Parameter(Mandatory)] $Evidence)
    Initialize-GraphKitAuthStageCapture
    return $script:GraphKitAuthStageCaptureType::HasInitialOwnerOnlyDirectoryAccess($Evidence)
}

function ConvertTo-GraphKitAuthCanonicalJsonBytes {
    param([Parameter(Mandatory)] $Value)
    $json = $Value | ConvertTo-Json -Depth 12 -Compress
    return [Text.UTF8Encoding]::new($false, $true).GetBytes($json)
}

function Get-GraphKitAuthSha256 {
    param([Parameter(Mandatory)][byte[]] $Bytes)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Test-GraphKitAuthBytesEqual {
    param([Parameter(Mandatory)][byte[]] $Left, [Parameter(Mandatory)][byte[]] $Right)
    if ($Left.Length -ne $Right.Length) { return $false }
    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -ne $Right[$index]) { return $false }
    }
    return $true
}

function Test-GraphKitAuthSealedStage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $StagePath,
        [Parameter(Mandatory)][string] $FullVersion
    )
    Initialize-GraphKitAuthStageCapture
    Assert-GraphKitAuthSafeSegment -Value $FullVersion -Kind 'full version'
    $stage = [IO.Path]::GetFullPath($StagePath)
    if (-not (Test-Path -LiteralPath $stage -PathType Container)) { throw "GraphKit.Auth stage '$stage' is missing." }
    $digestName = [IO.Path]::GetFileName($stage)
    if ($digestName -cnotmatch '^[0-9a-f]{64}$') { throw "GraphKit.Auth stage '$stage' is not digest-named." }
    $versionRoot = Split-Path $stage -Parent
    if ([IO.Path]::GetFileName($versionRoot) -cne $FullVersion) {
        throw "GraphKit.Auth stage version does not match '$FullVersion'."
    }

    Assert-GraphKitAuthExactDirectoryClosure -Directory $stage -ExpectedNames @('manifest.json','payload') -Kind 'stage envelope'
    $stageRoot = Split-Path $versionRoot -Parent
    $versionEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory($stageRoot, $FullVersion)
    $envelope = $script:GraphKitAuthStageCaptureType::InspectDirectory($versionRoot, $digestName)
    $manifestEvidence = $script:GraphKitAuthStageCaptureType::InspectFile($stage, 'manifest.json')
    if ($manifestEvidence.LinkCount -ne 1) { throw 'The GraphKit.Auth manifest is not link-count one.' }
    if ($manifestEvidence.Sha256 -cne $digestName) { throw 'The GraphKit.Auth manifest digest does not match its stage path.' }
    if (-not (Test-GraphKitAuthSealedPermission $versionEvidence $true) -or
        -not (Test-GraphKitAuthSealedPermission $envelope $true) -or
        -not (Test-GraphKitAuthSealedPermission $manifestEvidence $false)) {
        throw 'The GraphKit.Auth version, envelope, or manifest is writable or has the wrong permission policy.'
    }

    $manifestBytes = $script:GraphKitAuthStageCaptureType::ReadFile($stage, 'manifest.json')
    try { $manifest = [Text.UTF8Encoding]::new($false, $true).GetString($manifestBytes) | ConvertFrom-Json -Depth 12 }
    catch { throw "The GraphKit.Auth canonical manifest is invalid JSON: $($_.Exception.Message)" }
    if ((Get-GraphKitAuthSha256 $manifestBytes) -cne $digestName) { throw 'The GraphKit.Auth manifest changed during validation.' }
    $canonical = ConvertTo-GraphKitAuthCanonicalJsonBytes $manifest
    if (-not (Test-GraphKitAuthBytesEqual $manifestBytes $canonical)) {
        throw 'The GraphKit.Auth manifest is not canonical UTF-8 JSON.'
    }
    if (($manifest.PSObject.Properties.Name -join '|') -cne 'schemaVersion|fullVersion|permissions|directories|files|manifest' -or
        [int]$manifest.schemaVersion -ne 1 -or [string]$manifest.fullVersion -cne $FullVersion) {
        throw 'The GraphKit.Auth manifest schema or version is invalid.'
    }
    if (($manifest.permissions.PSObject.Properties.Name -join '|') -cne 'file|directory' -or
        [string]$manifest.permissions.file -cne $(if ($IsWindows) { 'windows-owner-read' } else { 'unix-0400' }) -or
        [string]$manifest.permissions.directory -cne $(if ($IsWindows) { 'windows-owner-read-execute' } else { 'unix-0500' })) {
        throw 'The GraphKit.Auth manifest permission policy is invalid.'
    }
    if (($manifest.directories.PSObject.Properties.Name -join '|') -cne 'envelope|payload' -or
        ($manifest.directories.envelope.PSObject.Properties.Name -join '|') -cne 'nativeIdentity' -or
        ($manifest.directories.payload.PSObject.Properties.Name -join '|') -cne 'nativeIdentity') {
        throw 'The GraphKit.Auth directory evidence schema is invalid.'
    }
    if ([string]$manifest.directories.envelope.nativeIdentity -cne [string]$envelope.NativeIdentity) {
        throw 'The GraphKit.Auth envelope native identity changed.'
    }

    $payloadEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory($stage, 'payload')
    if ([string]$manifest.directories.payload.nativeIdentity -cne [string]$payloadEvidence.NativeIdentity -or
        -not (Test-GraphKitAuthSealedPermission $payloadEvidence $true) -or
        -not (Test-GraphKitAuthContainedPhysicalPath $envelope.PhysicalPath $payloadEvidence.PhysicalPath)) {
        throw 'The GraphKit.Auth payload directory identity, containment, or permission policy is invalid.'
    }
    Assert-GraphKitAuthExactDirectoryClosure -Directory (Join-Path $stage 'payload') -ExpectedNames $script:GraphKitAuthPayloadFiles -Kind 'payload'
    if (@($manifest.files).Count -ne $script:GraphKitAuthPayloadFiles.Count) { throw 'The GraphKit.Auth manifest file count is invalid.' }
    $expectedManifestPaths = @($script:GraphKitAuthPayloadFiles | ForEach-Object { "payload/$_" })
    $manifestPaths = @($manifest.files | ForEach-Object { [string]$_.path })
    if (($manifestPaths -join '|') -cne ($expectedManifestPaths -join '|')) { throw 'The GraphKit.Auth manifest file order or closure is invalid.' }
    foreach ($record in @($manifest.files)) {
        if (($record.PSObject.Properties.Name -join '|') -cne 'path|length|sha256|nativeIdentity|linkCount') {
            throw "The GraphKit.Auth file evidence schema is invalid for '$($record.path)'."
        }
        $relative = [string]$record.path
        if ($relative.IndexOf('\') -ge 0 -or -not $relative.IsNormalized([Text.NormalizationForm]::FormC)) {
            throw "The GraphKit.Auth manifest path '$relative' is unsafe."
        }
        $fileEvidence = $script:GraphKitAuthStageCaptureType::InspectFile($stage, $relative)
        if ($fileEvidence.LinkCount -ne 1 -or [long]$record.linkCount -ne 1 -or
            [long]$record.length -ne $fileEvidence.Length -or [string]$record.sha256 -cne [string]$fileEvidence.Sha256 -or
            [string]$record.nativeIdentity -cne [string]$fileEvidence.NativeIdentity -or
            -not (Test-GraphKitAuthSealedPermission $fileEvidence $false) -or
            -not (Test-GraphKitAuthContainedPhysicalPath $payloadEvidence.PhysicalPath $fileEvidence.PhysicalPath)) {
            throw "The GraphKit.Auth payload evidence failed for '$relative'."
        }
    }
    if (($manifest.manifest.PSObject.Properties.Name -join '|') -cne 'linkCount' -or [long]$manifest.manifest.linkCount -ne 1) {
        throw 'The GraphKit.Auth manifest policy record is invalid.'
    }
    return [pscustomobject]@{
        StagePath = $stage
        PayloadPath = Join-Path $stage 'payload'
        ManifestPath = Join-Path $stage 'manifest.json'
        ManifestSha256 = $digestName
        FullVersion = $FullVersion
        Manifest = $manifest
    }
}

function New-GraphKitAuthSealedStage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $OutputRoot,
        [Parameter(Mandatory)][string] $FullVersion,
        [Parameter(Mandatory)][string] $PayloadSourceRoot,
        [scriptblock] $BeforeVersionInstall,
        [scriptblock] $AfterOwnedDirectoryCreate,
        [scriptblock] $AfterVersionDestinationCheck
    )
    Initialize-GraphKitAuthStageCapture
    Assert-GraphKitAuthSafeSegment -Value $FullVersion -Kind 'full version'
    $source = [IO.Path]::GetFullPath($PayloadSourceRoot)
    Assert-GraphKitAuthExactDirectoryClosure -Directory $source -ExpectedNames $script:GraphKitAuthPayloadFiles -Kind 'capture source'
    $authRoot = Get-GraphKitAuthOutputRoot $OutputRoot
    $authParent = Split-Path $authRoot -Parent
    if (-not (Test-Path -LiteralPath $authParent -PathType Container)) {
        $null = [IO.Directory]::CreateDirectory($authParent)
    }
    $authParentParent = Split-Path $authParent -Parent
    $authParentName = [IO.Path]::GetFileName($authParent)
    $authParentEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory(
        $authParentParent, $authParentName)
    $authEvidence = Initialize-GraphKitAuthOwnerDirectory -ParentPath $authParent `
        -ParentEvidence $authParentEvidence -ChildName ([IO.Path]::GetFileName($authRoot)) `
        -Kind 'auth root' -AfterChildInspection $AfterOwnedDirectoryCreate
    $captureRoot = Join-Path $authRoot 'capture'
    $stageRoot = Join-Path $authRoot 'stage'
    $versionRoot = Join-Path $stageRoot $FullVersion
    $captureRootEvidence = Initialize-GraphKitAuthOwnerDirectory -ParentPath $authRoot `
        -ParentEvidence $authEvidence -ChildName 'capture' -Kind 'capture root' `
        -AfterChildInspection $AfterOwnedDirectoryCreate
    $stageRootEvidence = Initialize-GraphKitAuthOwnerDirectory -ParentPath $authRoot `
        -ParentEvidence $authEvidence -ChildName 'stage' -Kind 'stage root' `
        -AfterChildInspection $AfterOwnedDirectoryCreate
    $runId = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(24)).ToLowerInvariant()
    $capture = Join-Path $captureRoot $runId
    $payload = Join-Path $capture 'payload'
    $installName = ".install-$runId"
    $installRoot = Join-Path $stageRoot $installName
    $temporaryVersionRoot = Join-Path $installRoot $FullVersion
    $captureEvidence = $null
    $payloadEvidence = $null
    $installEvidence = $null
    $temporaryVersionEvidence = $null
    $candidateStagePath = $null
    $manifestWrite = $null
    $capturedFileEvidence = [ordered]@{}
    try {
        $captureEvidence = Initialize-GraphKitAuthOwnerDirectory -ParentPath $captureRoot `
            -ParentEvidence $captureRootEvidence -ChildName $runId -Kind 'capture envelope' `
            -AfterChildInspection $AfterOwnedDirectoryCreate
        $payloadEvidence = Initialize-GraphKitAuthOwnerDirectory -ParentPath $capture `
            -ParentEvidence $captureEvidence -ChildName 'payload' -Kind 'capture payload' `
            -AfterChildInspection $AfterOwnedDirectoryCreate
        $records = [Collections.Generic.List[object]]::new()
        foreach ($name in $script:GraphKitAuthPayloadFiles) {
            $copy = $script:GraphKitAuthStageCaptureType::CopyFileCreateNew(
                $source, $name, $payload, $name, $true)
            $capturedFileEvidence[$name] = $copy.Destination
            if ($copy.Source.LinkCount -ne 1 -or $copy.Destination.LinkCount -ne 1) {
                throw "GraphKit.Auth capture source or destination '$name' is not link-count one."
            }
            $records.Add([ordered]@{
                path = "payload/$name"
                length = [long]$copy.Destination.Length
                sha256 = [string]$copy.Destination.Sha256
                nativeIdentity = [string]$copy.Destination.NativeIdentity
                linkCount = [long]1
            })
        }
        Assert-GraphKitAuthExactDirectoryClosure -Directory $payload -ExpectedNames $script:GraphKitAuthPayloadFiles -Kind 'new capture payload'
        $envelopeEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory($captureRoot, $runId)
        $payloadEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory($capture, 'payload')
        $manifest = [ordered]@{
            schemaVersion = 1
            fullVersion = $FullVersion
            permissions = [ordered]@{
                file = if ($IsWindows) { 'windows-owner-read' } else { 'unix-0400' }
                directory = if ($IsWindows) { 'windows-owner-read-execute' } else { 'unix-0500' }
            }
            directories = [ordered]@{
                envelope = [ordered]@{ nativeIdentity = [string]$envelopeEvidence.NativeIdentity }
                payload = [ordered]@{ nativeIdentity = [string]$payloadEvidence.NativeIdentity }
            }
            files = @($records)
            manifest = [ordered]@{ linkCount = [long]1 }
        }
        $manifestBytes = ConvertTo-GraphKitAuthCanonicalJsonBytes $manifest
        $manifestWrite = $script:GraphKitAuthStageCaptureType::WriteFileCreateNew(
            $capture, 'manifest.json', $manifestBytes, $true)
        $manifestPath = Join-Path $capture 'manifest.json'
        foreach ($name in $script:GraphKitAuthPayloadFiles) {
            $script:GraphKitAuthStageCaptureType::SetOwnerOnly((Join-Path $payload $name), $false, $false)
        }
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly($manifestPath, $false, $false)
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly($payload, $true, $false)
        $installEvidence = Initialize-GraphKitAuthOwnerDirectory -ParentPath $stageRoot `
            -ParentEvidence $stageRootEvidence -ChildName $installName -Kind 'temporary install root' `
            -AfterChildInspection $AfterOwnedDirectoryCreate
        $temporaryVersionEvidence = Initialize-GraphKitAuthOwnerDirectory -ParentPath $installRoot `
            -ParentEvidence $installEvidence -ChildName $FullVersion -Kind 'temporary version root' `
            -AfterChildInspection $AfterOwnedDirectoryCreate
        $digest = Get-GraphKitAuthSha256 $manifestBytes
        $candidateStagePath = Join-Path $temporaryVersionRoot $digest
        [IO.Directory]::Move($capture, $candidateStagePath)
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly($candidateStagePath, $true, $false)
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly($temporaryVersionRoot, $true, $false)
        $null = Test-GraphKitAuthSealedStage -StagePath $candidateStagePath -FullVersion $FullVersion
        if ($null -ne $BeforeVersionInstall) {
            & $BeforeVersionInstall $temporaryVersionRoot
        }
        $preMoveVersionEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory(
            $installRoot, $FullVersion)
        if ([string]$preMoveVersionEvidence.NativeIdentity -cne [string]$temporaryVersionEvidence.NativeIdentity -or
            [string]$preMoveVersionEvidence.PhysicalPath -cne [string]$temporaryVersionEvidence.PhysicalPath) {
            throw 'The GraphKit.Auth temporary version wrapper changed before atomic installation.'
        }
        $versionEntry = Get-GraphKitAuthPortableChildEntry -ParentPath $stageRoot `
            -ChildName $FullVersion -Kind 'stage version'
        if ($versionEntry.Exists) {
            throw "The GraphKit.Auth stage version '$FullVersion' already exists."
        }
        if ($null -ne $AfterVersionDestinationCheck) {
            & $AfterVersionDestinationCheck $temporaryVersionRoot $versionRoot
        }
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly($temporaryVersionRoot, $true, $true)
        $movedVersion = $false
        try {
            $script:GraphKitAuthStageCaptureType::MoveDirectoryCreateNew(
                $temporaryVersionRoot, $versionRoot)
            $movedVersion = $true
        }
        finally {
            $moveParent = if ($movedVersion) { $stageRoot } else { $installRoot }
            $movePath = if ($movedVersion) { $versionRoot } else { $temporaryVersionRoot }
            $currentVersionEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory(
                $moveParent, $FullVersion)
            if ([string]$currentVersionEvidence.NativeIdentity -cne [string]$temporaryVersionEvidence.NativeIdentity) {
                throw 'The GraphKit.Auth version wrapper changed during atomic installation; resealing was refused.'
            }
            $script:GraphKitAuthStageCaptureType::SetOwnerOnly($movePath, $true, $false)
        }
        $finalVersionEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory(
            $stageRoot, $FullVersion)
        if ([string]$finalVersionEvidence.NativeIdentity -cne [string]$temporaryVersionEvidence.NativeIdentity -or
            -not (Test-GraphKitAuthContainedPhysicalPath $stageRootEvidence.PhysicalPath $finalVersionEvidence.PhysicalPath)) {
            throw 'The GraphKit.Auth atomic version install did not preserve its native identity and containment.'
        }
        $currentInstall = $script:GraphKitAuthStageCaptureType::InspectDirectory($stageRoot, $installName)
        if ([string]$currentInstall.NativeIdentity -cne [string]$installEvidence.NativeIdentity -or
            [string]$currentInstall.PhysicalPath -cne [string]$installEvidence.PhysicalPath -or
            @([IO.Directory]::EnumerateFileSystemEntries($installRoot)).Count -ne 0) {
            throw 'The GraphKit.Auth successful install left an ambiguous temporary wrapper.'
        }
        Remove-Item -LiteralPath $installRoot -Force -ErrorAction Stop
        $finalPath = Join-Path $versionRoot $digest
        $verified = Test-GraphKitAuthSealedStage -StagePath $finalPath -FullVersion $FullVersion
        $verified | Add-Member -MemberType NoteProperty -Name ManifestInitialEvidence `
            -Value $manifestWrite.DestinationInitial -Force
        return $verified
    }
    catch {
        $primary = $_
        $cleanupFailures = [Collections.Generic.List[string]]::new()
        if ($null -ne $captureEvidence) {
            try {
                $captureEntry = Get-GraphKitAuthPortableChildEntry -ParentPath $captureRoot `
                    -ChildName $runId -Kind 'capture envelope cleanup'
                if ($captureEntry.Exists) {
                    if ($null -ne $payloadEvidence) {
                        Remove-GraphKitAuthVerifiedCaptureCandidate -CaptureRoot $captureRoot `
                            -CaptureName $runId -CaptureEvidence $captureEvidence `
                            -PayloadEvidence $payloadEvidence -CapturedFileEvidence $capturedFileEvidence `
                            -ManifestWrite $manifestWrite
                    }
                    else {
                        Remove-GraphKitAuthVerifiedEmptyDirectory -ParentPath $captureRoot `
                            -ParentEvidence $captureRootEvidence -ChildName $runId `
                            -ChildEvidence $captureEvidence -Kind 'empty capture envelope cleanup'
                    }
                }
            }
            catch { $cleanupFailures.Add($_.Exception.Message) }
        }
        if ($null -ne $candidateStagePath -and (Test-Path -LiteralPath $candidateStagePath -PathType Container)) {
            try {
                Remove-GraphKitAuthVerifiedInstallCandidate -StageRoot $stageRoot `
                    -InstallName $installName -InstallEvidence $installEvidence `
                    -FullVersion $FullVersion -TemporaryVersionEvidence $temporaryVersionEvidence `
                    -CandidateStagePath $candidateStagePath
            }
            catch { $cleanupFailures.Add($_.Exception.Message) }
        }
        elseif ($null -ne $installEvidence) {
            try {
                $installEntry = Get-GraphKitAuthPortableChildEntry -ParentPath $stageRoot `
                    -ChildName $installName -Kind 'temporary install cleanup'
                if ($installEntry.Exists) {
                    $temporaryVersionEntry = Get-GraphKitAuthPortableChildEntry -ParentPath $installRoot `
                        -ChildName $FullVersion -Kind 'temporary version cleanup'
                    if ($null -ne $temporaryVersionEvidence -and $temporaryVersionEntry.Exists) {
                        Remove-GraphKitAuthVerifiedEmptyInstallCandidate -StageRoot $stageRoot `
                            -InstallName $installName -InstallEvidence $installEvidence `
                            -FullVersion $FullVersion -TemporaryVersionEvidence $temporaryVersionEvidence
                    }
                    elseif (-not $temporaryVersionEntry.Exists) {
                        Remove-GraphKitAuthVerifiedEmptyDirectory -ParentPath $stageRoot `
                            -ParentEvidence $stageRootEvidence -ChildName $installName `
                            -ChildEvidence $installEvidence -Kind 'empty temporary install cleanup'
                    }
                    else {
                        throw 'The GraphKit.Auth temporary version has no ownership evidence; ambiguous cleanup was refused.'
                    }
                }
            }
            catch { $cleanupFailures.Add($_.Exception.Message) }
        }
        if ($cleanupFailures.Count -ne 0) {
            throw "GraphKit.Auth stage creation failed and ambiguous cleanup was refused: $($cleanupFailures -join ' | ') Original failure: $($primary.Exception.Message)"
        }
        if ($primary.Exception.Message -match 'portable alias|stage version .* already exists\.$') {
            throw $primary
        }
        $finalMatches = @([IO.Directory]::EnumerateFileSystemEntries($stageRoot) | Where-Object {
            [IO.Path]::GetFileName($_) -ceq $FullVersion
        })
        if ($finalMatches.Count -eq 1) {
            throw "GraphKit.Auth stage version '$FullVersion' already exists or won the atomic install: $($primary.Exception.Message)"
        }
        throw $primary
    }
}

function Invoke-GraphKitAuthPrepareClean {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $OutputRoot)
    Initialize-GraphKitAuthStageCapture
    $authRoot = Get-GraphKitAuthOutputRoot $OutputRoot
    $authParent = Split-Path $authRoot -Parent
    if (-not (Test-Path -LiteralPath $authParent -PathType Container)) { return @() }
    $authEntry = Get-GraphKitAuthPortableChildEntry -ParentPath $authParent `
        -ChildName ([IO.Path]::GetFileName($authRoot)) -Kind 'Prepare auth root'
    if (-not $authEntry.Exists) { return @() }
    $authParentParent = Split-Path $authParent -Parent
    $authParentName = [IO.Path]::GetFileName($authParent)
    $authParentEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory(
        $authParentParent, $authParentName)
    $authEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory(
        $authParent, [IO.Path]::GetFileName($authRoot))
    if (-not (Test-GraphKitAuthContainedPhysicalPath $authParentEvidence.PhysicalPath $authEvidence.PhysicalPath)) {
        throw 'The GraphKit.Auth Prepare auth root is not physically contained.'
    }
    if (-not (Test-GraphKitAuthOwnerOnlyWritableDirectory $authEvidence)) {
        throw 'The GraphKit.Auth Prepare auth root is not exact current-owner-only writable.'
    }
    $captureEntry = Get-GraphKitAuthPortableChildEntry -ParentPath $authRoot `
        -ChildName 'capture' -Kind 'Prepare capture root'
    if (-not $captureEntry.Exists) {
        throw 'The GraphKit.Auth Prepare capture root is missing from a partial output tree.'
    }
    $captureEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory($authRoot, 'capture')
    if (-not (Test-GraphKitAuthContainedPhysicalPath $authEvidence.PhysicalPath $captureEvidence.PhysicalPath)) {
        throw 'The GraphKit.Auth Prepare capture root is not physically contained.'
    }
    if (-not (Test-GraphKitAuthOwnerOnlyWritableDirectory $captureEvidence)) {
        throw 'The GraphKit.Auth Prepare capture root is not exact current-owner-only writable.'
    }
    Assert-GraphKitAuthExactDirectoryClosure -Directory $captureEntry.Path `
        -ExpectedNames @() -Kind 'Prepare capture root, which must be empty'
    $stageEntry = Get-GraphKitAuthPortableChildEntry -ParentPath $authRoot `
        -ChildName 'stage' -Kind 'Prepare stage root'
    if (-not $stageEntry.Exists) { return @() }
    $stageRoot = Join-Path $authRoot 'stage'
    $stageRootEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory($authRoot, 'stage')
    if (-not (Test-GraphKitAuthContainedPhysicalPath $authEvidence.PhysicalPath $stageRootEvidence.PhysicalPath)) {
        throw 'The GraphKit.Auth Prepare stage root is not physically contained.'
    }
    if (-not (Test-GraphKitAuthOwnerOnlyWritableDirectory $stageRootEvidence)) {
        throw 'The GraphKit.Auth Prepare stage root is not exact current-owner-only writable.'
    }
    $verified = [Collections.Generic.List[object]]::new()
    $versionPaths = @([IO.Directory]::EnumerateFileSystemEntries($stageRoot))
    $versionNames = @($versionPaths | ForEach-Object { [IO.Path]::GetFileName($_) })
    Assert-GraphKitAuthPortableNameSet -Names $versionNames -Kind 'stage version namespace'
    foreach ($versionPath in $versionPaths) {
        $version = [IO.Path]::GetFileName($versionPath)
        $versionEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory($stageRoot, $version)
        if (-not (Test-GraphKitAuthContainedPhysicalPath $stageRootEvidence.PhysicalPath $versionEvidence.PhysicalPath) -or
            -not (Test-GraphKitAuthSealedPermission $versionEvidence $true)) {
            throw "GraphKit.Auth prior stage version '$version' is linked, escaped, or writable."
        }
        $digests = @([IO.Directory]::EnumerateFileSystemEntries($versionPath))
        if ($digests.Count -ne 1) { throw "GraphKit.Auth prior stage version '$version' is not an exact envelope container." }
        $verified.Add((Test-GraphKitAuthSealedStage -StagePath $digests[0] -FullVersion $version))
    }
    foreach ($stage in $verified) {
        foreach ($file in @($stage.Manifest.files)) {
            $script:GraphKitAuthStageCaptureType::SetOwnerOnly((Join-Path $stage.StagePath ([string]$file.path)), $false, $true)
        }
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly($stage.ManifestPath, $false, $true)
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly($stage.PayloadPath, $true, $true)
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly($stage.StagePath, $true, $true)
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly((Split-Path $stage.StagePath -Parent), $true, $true)
    }
    return @($verified)
}

function Invoke-GraphKitAuthLiteralQuarantine {
    param([Parameter(Mandatory)][string] $RepositoryRoot)
    # Directory.Move is the identity-preserving quarantine primitive. Keep its
    # destination beneath the repository output tree so source and destination
    # remain on the same volume instead of depending on the OS temp volume.
    $quarantine = Join-Path (Join-Path $RepositoryRoot 'output') `
        ('GraphKit.Auth.quarantine-' + [guid]::NewGuid().ToString('N'))
    $null = [IO.Directory]::CreateDirectory($quarantine)
    $relativeRoots = @(
        'src/GraphKit.Auth/GraphKit.Auth.Contracts/bin'
        'src/GraphKit.Auth/GraphKit.Auth.Contracts/obj'
        'src/GraphKit.Auth/GraphKit.Auth/bin'
        'src/GraphKit.Auth/GraphKit.Auth/obj'
        'src/GraphKit.Auth/GraphKit.Auth.Tests/bin'
        'src/GraphKit.Auth/GraphKit.Auth.Tests/obj'
        'src/GraphKit.Auth/GraphKit.Auth.Tests/TestResults'
    )
    foreach ($relative in $relativeRoots) {
        $source = Join-Path $RepositoryRoot $relative
        if (Test-Path -LiteralPath $source) {
            $destination = Join-Path $quarantine ($relative.Replace('/', '__'))
            [IO.Directory]::Move([IO.Path]::GetFullPath($source), $destination)
        }
    }
    return $quarantine
}

function Restore-GraphKitAuthGitConfigEnvironment {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Environment)
    foreach ($entry in @(Get-ChildItem Env:)) {
        if ($entry.Name.StartsWith('GIT_CONFIG_', [StringComparison]::Ordinal)) {
            Remove-Item -LiteralPath "Env:$($entry.Name)" -ErrorAction Stop
        }
    }
    foreach ($entry in $Environment.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable([string]$entry.Key, [string]$entry.Value, 'Process')
    }
}

function Enable-GraphKitAuthAbiTestGitExcludes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $RepositoryRoot,
        [Parameter(Mandatory)][string[]] $Patterns,
        [scriptblock] $AfterFirstEnvironmentWrite
    )
    if ($null -ne $script:GraphKitAuthAbiGitConfigState) {
        throw 'The process already has an active GraphKit.Auth ABI-test Git exclusion scope.'
    }
    if ($Patterns.Count -ne 5 -or @($Patterns | Select-Object -Unique).Count -ne 5) {
        throw 'The GraphKit.Auth ABI-test exclusion inventory must contain exactly five unique entries.'
    }
    foreach ($pattern in $Patterns) {
        if ([string]::IsNullOrWhiteSpace($pattern) -or -not $pattern.StartsWith('/', [StringComparison]::Ordinal) -or
            $pattern.EndsWith('/', [StringComparison]::Ordinal) -or $pattern.IndexOfAny([char[]]'*?[') -ge 0 -or
            -not $pattern.IsNormalized([Text.NormalizationForm]::FormC)) {
            throw "The GraphKit.Auth ABI-test exclusion '$pattern' is not one root-anchored literal file pattern."
        }
    }

    $environment = [ordered]@{}
    foreach ($entry in Get-ChildItem Env:) {
        if ($entry.Name.StartsWith('GIT_CONFIG_', [StringComparison]::Ordinal)) {
            $environment[$entry.Name] = [string]$entry.Value
        }
    }
    $priorCountText = [Environment]::GetEnvironmentVariable('GIT_CONFIG_COUNT', 'Process')
    $priorCount = 0
    if ($null -ne $priorCountText -and
        (-not [int]::TryParse($priorCountText, [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture, [ref]$priorCount) -or $priorCount -lt 0)) {
        throw "The inherited GIT_CONFIG_COUNT '$priorCountText' is invalid."
    }
    $keyName = "GIT_CONFIG_KEY_$priorCount"
    $valueName = "GIT_CONFIG_VALUE_$priorCount"
    if ($null -ne [Environment]::GetEnvironmentVariable($keyName, 'Process') -or
        $null -ne [Environment]::GetEnvironmentVariable($valueName, 'Process')) {
        throw "The inherited process Git configuration collides at index $priorCount."
    }

    $excludePath = Join-Path ([IO.Path]::GetTempPath()) ('graphkit-auth-abi-excludes-' + [guid]::NewGuid().ToString('N'))
    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(($Patterns -join "`n") + "`n")
    $stream = [IO.FileStream]::new($excludePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }

    try {
        [Environment]::SetEnvironmentVariable($keyName, 'core.excludesFile', 'Process')
        if ($null -ne $AfterFirstEnvironmentWrite) { & $AfterFirstEnvironmentWrite }
        [Environment]::SetEnvironmentVariable($valueName, $excludePath, 'Process')
        [Environment]::SetEnvironmentVariable('GIT_CONFIG_COUNT', ($priorCount + 1).ToString([Globalization.CultureInfo]::InvariantCulture), 'Process')
        $script:GraphKitAuthAbiGitConfigState = [pscustomobject]@{
            Environment = $environment
            ExcludePath = $excludePath
        }
    }
    catch {
        Restore-GraphKitAuthGitConfigEnvironment -Environment $environment
        if (Test-Path -LiteralPath $excludePath -PathType Leaf) { [IO.File]::Delete($excludePath) }
        throw
    }
}

function Disable-GraphKitAuthAbiTestGitExcludes {
    [CmdletBinding()]
    param()
    $state = $script:GraphKitAuthAbiGitConfigState
    if ($null -eq $state) { return }
    try {
        Restore-GraphKitAuthGitConfigEnvironment -Environment $state.Environment
    }
    finally {
        if (Test-Path -LiteralPath $state.ExcludePath -PathType Leaf) { [IO.File]::Delete($state.ExcludePath) }
        $script:GraphKitAuthAbiGitConfigState = $null
    }
}

function Assert-GraphKitAuthAbiProjectedFileEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $RepositoryRoot,
        [Parameter(Mandatory)][string] $RelativePath,
        [Parameter(Mandatory)] $Expected
    )
    Initialize-GraphKitAuthStageCapture
    $repositoryRootEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectoryPath(
        $RepositoryRoot)
    $actual = $script:GraphKitAuthStageCaptureType::InspectFile($RepositoryRoot, $RelativePath)
    if (-not $actual.IsRegularFile -or $actual.IsReparsePoint -or [long]$actual.LinkCount -ne 1 -or
        -not (Test-GraphKitAuthContainedPhysicalPath `
            $repositoryRootEvidence.PhysicalPath $actual.PhysicalPath) -or
        [string]$actual.PhysicalPath -cne [string]$Expected.PhysicalPath -or
        [string]$actual.NativeIdentity -cne [string]$Expected.NativeIdentity -or
        [string]$actual.Sha256 -cne [string]$Expected.Sha256 -or
        [long]$actual.Length -ne [long]$Expected.Length -or
        [long]$actual.LinkCount -ne [long]$Expected.LinkCount) {
        throw "The projected GraphKit.Auth ABI-test file '$RelativePath' was replaced, linked, changed, or escaped."
    }
    return $actual
}

function New-GraphKitAuthAbiTestFixture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $RepositoryRoot,
        [Parameter(Mandatory)][string] $OutputRoot
    )
    Initialize-GraphKitAuthStageCapture
    $sourceManifest = Import-PowerShellDataFile -LiteralPath (Join-Path $RepositoryRoot 'source/GraphKit.psd1')
    $baseVersion = [string]$sourceManifest.ModuleVersion
    $builtManifestPath = Join-Path $RepositoryRoot "output/module/GraphKit/$baseVersion/GraphKit.psd1"
    if (-not (Test-Path -LiteralPath $builtManifestPath -PathType Leaf)) {
        throw "The GraphKit.Auth ABI test fixture has no built manifest at '$builtManifestPath'."
    }
    $builtManifest = Import-PowerShellDataFile -LiteralPath $builtManifestPath
    $prerelease = [string]$builtManifest.PrivateData.PSData.Prerelease
    $fullVersion = if ([string]::IsNullOrWhiteSpace($prerelease)) { $baseVersion } else { "$baseVersion-$prerelease" }
    $versionRoot = Join-Path (Get-GraphKitAuthOutputRoot $OutputRoot) "stage/$fullVersion"
    if (-not (Test-Path -LiteralPath $versionRoot -PathType Container)) {
        throw "The sealed GraphKit.Auth stage for ABI testing is missing at '$versionRoot'."
    }
    $stageEntries = @([IO.Directory]::EnumerateFileSystemEntries($versionRoot))
    if ($stageEntries.Count -ne 1 -or -not (Test-Path -LiteralPath $stageEntries[0] -PathType Container)) {
        throw 'The sealed GraphKit.Auth stage for ABI testing is not one exact digest envelope.'
    }
    $verified = Test-GraphKitAuthSealedStage -StagePath $stageEntries[0] -FullVersion $fullVersion
    $destinations = [ordered]@{
        'GraphKit.Auth.Contracts.dll' = 'src/GraphKit.Auth/GraphKit.Auth.Contracts/bin/Release/net8.0/GraphKit.Auth.Contracts.dll'
        'GraphKit.Auth.dll' = 'src/GraphKit.Auth/GraphKit.Auth/bin/Release/net8.0/GraphKit.Auth.dll'
        'GraphKit.Auth.deps.json' = 'src/GraphKit.Auth/GraphKit.Auth/bin/Release/net8.0/GraphKit.Auth.deps.json'
        'Microsoft.Identity.Client.dll' = 'src/GraphKit.Auth/GraphKit.Auth.Tests/bin/Release/net8.0/Microsoft.Identity.Client.dll'
        'Microsoft.IdentityModel.Abstractions.dll' = 'src/GraphKit.Auth/GraphKit.Auth.Tests/bin/Release/net8.0/Microsoft.IdentityModel.Abstractions.dll'
    }
    $binRoots = @(
        'src/GraphKit.Auth/GraphKit.Auth.Contracts/bin'
        'src/GraphKit.Auth/GraphKit.Auth/bin'
        'src/GraphKit.Auth/GraphKit.Auth.Tests/bin'
    ) | ForEach-Object { Join-Path $RepositoryRoot $_ }
    foreach ($binRoot in $binRoots) {
        if (Test-Path -LiteralPath $binRoot) {
            throw "The GraphKit.Auth ABI test fixture destination '$binRoot' already exists."
        }
    }
    $trainScript = Join-Path $RepositoryRoot 'scripts/Get-GraphKitTrainVersion.ps1'
    $baselineState = & $trainScript -RepositoryRoot $RepositoryRoot -AsObject
    $statusBefore = @(& git -C $RepositoryRoot status --porcelain=v1 --untracked-files=all)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot capture Git status before the GraphKit.Auth ABI-test projection.' }
    $patterns = @($destinations.Values | ForEach-Object { '/' + $_ })
    Enable-GraphKitAuthAbiTestGitExcludes -RepositoryRoot $RepositoryRoot -Patterns $patterns
    $script:GraphKitAuthAbiFixtureState = [pscustomobject]@{
        BaselineState = $baselineState
        StatusBefore = @($statusBefore)
        CreatedPaths = [Collections.Generic.List[string]]::new()
        CreatedDirectories = [Collections.Generic.List[string]]::new()
        Completed = $false
        ExpectedEvidence = [ordered]@{}
    }
    try {
        foreach ($entry in $destinations.GetEnumerator()) {
            $relativeFile = [string]$entry.Value
            $destinationFile = Join-Path $RepositoryRoot $relativeFile
            $destination = Split-Path $destinationFile -Parent
            $missingDirectories = [Collections.Generic.Stack[string]]::new()
            $candidateDirectory = [IO.Path]::GetFullPath($destination)
            while (-not [IO.Directory]::Exists($candidateDirectory)) {
                $missingDirectories.Push($candidateDirectory)
                $parentDirectory = [IO.Directory]::GetParent($candidateDirectory)
                if ($null -eq $parentDirectory) {
                    throw "The GraphKit.Auth ABI-test projection '$destination' has no existing ancestor."
                }
                $candidateDirectory = $parentDirectory.FullName
            }
            while ($missingDirectories.Count -gt 0) {
                $createdDirectory = $missingDirectories.Pop()
                $null = [IO.Directory]::CreateDirectory($createdDirectory)
                $script:GraphKitAuthAbiFixtureState.CreatedDirectories.Add($createdDirectory)
            }
            $copy = $script:GraphKitAuthStageCaptureType::CopyFileCreateNew(
                $verified.PayloadPath, $entry.Key, $destination, $entry.Key
            )
            $manifestRecord = @($verified.Manifest.files | Where-Object {
                [string]$_.path -ceq "payload/$($entry.Key)"
            })
            if ($manifestRecord.Count -ne 1 -or
                [string]$copy.Destination.Sha256 -cne [string]$manifestRecord[0].sha256 -or
                [long]$copy.Destination.LinkCount -ne 1) {
                throw "The GraphKit.Auth ABI test fixture '$($entry.Key)' does not match the sealed payload."
            }
            $script:GraphKitAuthAbiFixtureState.CreatedPaths.Add($destinationFile)
            $script:GraphKitAuthAbiFixtureState.ExpectedEvidence[$destinationFile] = $copy.Destination
            & git -C $RepositoryRoot check-ignore --quiet -- $relativeFile
            if ($LASTEXITCODE -ne 0) {
                throw "The exact GraphKit.Auth ABI-test projection '$relativeFile' is not excluded by its literal process scope."
            }
        }

        $hiddenState = & $trainScript -RepositoryRoot $RepositoryRoot -AsObject
        if ([string]$hiddenState.sourceStateSha256 -cne [string]$baselineState.sourceStateSha256 -or
            [string]$hiddenState.version -cne [string]$baselineState.version) {
            throw 'The exact GraphKit.Auth ABI-test projections changed the process-scoped source fingerprint.'
        }
        $sentinelRelative = '.graphkit-auth-abi-untracked-' + [guid]::NewGuid().ToString('N')
        $sentinelPath = Join-Path $RepositoryRoot $sentinelRelative
        try {
            $sentinelBytes = [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
            $sentinel = [IO.FileStream]::new($sentinelPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
                [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough)
            try { $sentinel.Write($sentinelBytes, 0, $sentinelBytes.Length); $sentinel.Flush($true) }
            finally { $sentinel.Dispose() }
            & git -C $RepositoryRoot check-ignore --quiet -- $sentinelRelative
            if ($LASTEXITCODE -eq 0) { throw 'The unrelated GraphKit.Auth ABI-test sentinel was unexpectedly excluded.' }
            if ($LASTEXITCODE -ne 1) {
                throw "The GraphKit.Auth ABI-test sentinel exclusion probe failed with git exit code '$LASTEXITCODE'; only exit 1 proves the sentinel is not ignored."
            }
            $sentinelState = & $trainScript -RepositoryRoot $RepositoryRoot -AsObject
            if ([string]$sentinelState.sourceStateSha256 -ceq [string]$hiddenState.sourceStateSha256) {
                throw 'An unrelated untracked source file did not change the dirty-source fingerprint.'
            }
        }
        finally {
            if (Test-Path -LiteralPath $sentinelPath -PathType Leaf) { [IO.File]::Delete($sentinelPath) }
        }
        $restoredHiddenState = & $trainScript -RepositoryRoot $RepositoryRoot -AsObject
        if ([string]$restoredHiddenState.sourceStateSha256 -cne [string]$hiddenState.sourceStateSha256) {
            throw 'The GraphKit.Auth ABI-test sentinel cleanup did not restore the projected source fingerprint.'
        }
        $script:GraphKitAuthAbiFixtureState.Completed = $true
    }
    catch {
        try { Remove-GraphKitAuthAbiTestFixture -RepositoryRoot $RepositoryRoot }
        catch { Write-Error -ErrorRecord $_ }
        throw
    }
    return @($binRoots)
}

function Remove-GraphKitAuthAbiTestFixture {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $RepositoryRoot)
    $state = $script:GraphKitAuthAbiFixtureState
    if ($null -eq $state) {
        Disable-GraphKitAuthAbiTestGitExcludes
        return
    }
    $failures = [Collections.Generic.List[string]]::new()
    $allowedFiles = @(
        'src/GraphKit.Auth/GraphKit.Auth.Contracts/bin/Release/net8.0/GraphKit.Auth.Contracts.dll'
        'src/GraphKit.Auth/GraphKit.Auth/bin/Release/net8.0/GraphKit.Auth.dll'
        'src/GraphKit.Auth/GraphKit.Auth/bin/Release/net8.0/GraphKit.Auth.deps.json'
        'src/GraphKit.Auth/GraphKit.Auth.Tests/bin/Release/net8.0/Microsoft.Identity.Client.dll'
        'src/GraphKit.Auth/GraphKit.Auth.Tests/bin/Release/net8.0/Microsoft.IdentityModel.Abstractions.dll'
    ) | ForEach-Object { Join-Path $RepositoryRoot $_ }
    $allowedFileSet = [Collections.Generic.HashSet[string]]::new(
        $(if ($IsWindows) { [StringComparer]::OrdinalIgnoreCase } else { [StringComparer]::Ordinal }))
    foreach ($file in $allowedFiles) { $null = $allowedFileSet.Add([IO.Path]::GetFullPath($file)) }
    $literalParents = @(
        'src/GraphKit.Auth/GraphKit.Auth.Contracts/bin/Release/net8.0'
        'src/GraphKit.Auth/GraphKit.Auth.Contracts/bin/Release'
        'src/GraphKit.Auth/GraphKit.Auth.Contracts/bin'
        'src/GraphKit.Auth/GraphKit.Auth/bin/Release/net8.0'
        'src/GraphKit.Auth/GraphKit.Auth/bin/Release'
        'src/GraphKit.Auth/GraphKit.Auth/bin'
        'src/GraphKit.Auth/GraphKit.Auth.Tests/bin/Release/net8.0'
        'src/GraphKit.Auth/GraphKit.Auth.Tests/bin/Release'
        'src/GraphKit.Auth/GraphKit.Auth.Tests/bin'
    ) | ForEach-Object { Join-Path $RepositoryRoot $_ }
    $allowedParentSet = [Collections.Generic.HashSet[string]]::new(
        $(if ($IsWindows) { [StringComparer]::OrdinalIgnoreCase } else { [StringComparer]::Ordinal }))
    foreach ($parent in $literalParents) {
        $null = $allowedParentSet.Add([IO.Path]::GetFullPath($parent))
    }
    $createdPaths = @($state.CreatedPaths | ForEach-Object { [IO.Path]::GetFullPath([string]$_) })
    try {
        foreach ($file in $createdPaths) {
            if (-not $allowedFileSet.Contains($file) -or -not $state.ExpectedEvidence.Contains($file)) {
                $failures.Add("unregistered or out-of-bound projected path '$file'")
                continue
            }
            if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
                $failures.Add("missing recorded projected file '$file'")
                continue
            }
            $relativeFile = [IO.Path]::GetRelativePath($RepositoryRoot, $file).Replace('\', '/')
            try {
                $null = Assert-GraphKitAuthAbiProjectedFileEvidence -RepositoryRoot $RepositoryRoot `
                    -RelativePath $relativeFile -Expected $state.ExpectedEvidence[$file]
            }
            catch {
                $failures.Add($_.Exception.Message)
                continue
            }
            [IO.File]::Delete($file)
        }
        $createdParents = if ($null -ne $state.PSObject.Properties['CreatedDirectories']) {
            @($state.CreatedDirectories | ForEach-Object { [IO.Path]::GetFullPath([string]$_) })
        }
        else {
            @($literalParents | Where-Object {
                $parentPrefix = [IO.Path]::GetFullPath($_).TrimEnd(
                    [IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar
                ) + [IO.Path]::DirectorySeparatorChar
                @($createdPaths | Where-Object {
                    $_.StartsWith($parentPrefix, $(if ($IsWindows) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }))
                }).Count -ne 0
            })
        }
        $createdParents = @($createdParents | Sort-Object Length -Descending -Unique)
        foreach ($directory in $createdParents) {
            if (-not $allowedParentSet.Contains($directory)) {
                $failures.Add("unregistered or out-of-bound projected directory '$directory'")
                continue
            }
            if (-not (Test-Path -LiteralPath $directory -PathType Container)) { continue }
            if (@([IO.Directory]::EnumerateFileSystemEntries($directory)).Count -ne 0) {
                $failures.Add("non-empty projected parent '$directory'")
                continue
            }
            [IO.Directory]::Delete($directory, $false)
        }
    }
    finally {
        Disable-GraphKitAuthAbiTestGitExcludes
        $script:GraphKitAuthAbiFixtureState = $null
    }
    if ($null -ne $state.BaselineState) {
        $trainScript = Join-Path $RepositoryRoot 'scripts/Get-GraphKitTrainVersion.ps1'
        $restoredState = & $trainScript -RepositoryRoot $RepositoryRoot -AsObject
        $statusAfter = @(& git -C $RepositoryRoot status --porcelain=v1 --untracked-files=all)
        if ($LASTEXITCODE -ne 0) { $failures.Add('cannot capture Git status after ABI-test cleanup') }
        if ([string]$restoredState.sourceStateSha256 -cne [string]$state.BaselineState.sourceStateSha256 -or
            (@($statusAfter) -join "`n") -cne (@($state.StatusBefore) -join "`n")) {
            $failures.Add('source fingerprint or Git status was not restored after ABI-test cleanup')
        }
    }
    if ($failures.Count -ne 0) {
        throw "GraphKit.Auth ABI-test cleanup failed: $($failures -join '; ')."
    }
}

if (-not $SkipTaskRegistration -and (Get-Command task -ErrorAction SilentlyContinue)) {
    task Prepare_GraphKitAuth_Clean {
        Invoke-GraphKitAuthPrepareClean -OutputRoot (Join-Path $BuildRoot 'output') | Out-Null
    }

    task Build_GraphKitAuth {
        Initialize-GraphKitAuthStageCapture
        $solution = Join-Path $BuildRoot 'src/GraphKit.Auth/GraphKit.Auth.sln'
        $providerProject = Join-Path $BuildRoot 'src/GraphKit.Auth/GraphKit.Auth/GraphKit.Auth.csproj'
        $testProject = Join-Path $BuildRoot 'src/GraphKit.Auth/GraphKit.Auth.Tests/GraphKit.Auth.Tests.csproj'
        $runId = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(24)).ToLowerInvariant()
        $authOutput = Join-Path $BuildRoot 'output/GraphKit.Auth'
        $publishRoot = Join-Path $authOutput "publish/$runId"
        $providerPublish = Join-Path $publishRoot 'provider'
        $payloadSource = Join-Path $publishRoot 'payload'
        $resultRoot = Join-Path $authOutput "dotnet-test/$runId"
        $quarantine = $null
        $primaryFailure = $null
        try {
            $null = Initialize-GraphKitAuthBuildAuthorityRoot -OutputRoot (Join-Path $BuildRoot 'output')
            $dotnetVersionOutput = @(& dotnet --version)
            if ($LASTEXITCODE -ne 0) { throw 'GraphKit.Auth could not query the dotnet SDK version.' }
            $dotnetVersion = ([string] (@($dotnetVersionOutput | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            }) | Select-Object -Last 1)).Trim()
            if ($dotnetVersion -cne '10.0.400') { throw 'GraphKit.Auth requires dotnet SDK 10.0.400 exactly.' }
            & dotnet restore $solution --locked-mode
            if ($LASTEXITCODE -ne 0) { throw 'GraphKit.Auth locked restore failed.' }
            & dotnet build $solution -c Release --no-restore
            if ($LASTEXITCODE -ne 0) { throw 'GraphKit.Auth Release build failed.' }
            $null = [IO.Directory]::CreateDirectory($resultRoot)
            & dotnet test $testProject -c Release --no-build --no-restore --logger "trx;LogFileName=GraphKit.Auth.trx" --results-directory $resultRoot
            if ($LASTEXITCODE -ne 0) { throw 'GraphKit.Auth Release tests failed.' }
            $trxPath = Join-Path $resultRoot 'GraphKit.Auth.trx'
            [xml]$trx = Get-Content -LiteralPath $trxPath -Raw
            Assert-GraphKitAuthTestResult -Result $trx
            $null = [IO.Directory]::CreateDirectory($providerPublish)
            & dotnet publish $providerProject -c Release --no-build --no-restore --no-self-contained -o $providerPublish
            if ($LASTEXITCODE -ne 0) { throw 'GraphKit.Auth provider publish failed.' }
            Assert-GraphKitAuthExactDirectoryClosure -Directory $providerPublish -ExpectedNames $script:GraphKitAuthProviderFiles -Kind 'raw provider publish'
            $builtProvider = Join-Path $BuildRoot 'src/GraphKit.Auth/GraphKit.Auth/bin/Release/net8.0/GraphKit.Auth.dll'
            $builtContracts = Join-Path $BuildRoot 'src/GraphKit.Auth/GraphKit.Auth.Contracts/bin/Release/net8.0/GraphKit.Auth.Contracts.dll'
            $builtProviderDeps = Join-Path $BuildRoot 'src/GraphKit.Auth/GraphKit.Auth/bin/Release/net8.0/GraphKit.Auth.deps.json'
            $testOutput = Join-Path $BuildRoot 'src/GraphKit.Auth/GraphKit.Auth.Tests/bin/Release/net8.0'
            $lineagePairs = @(
                [pscustomobject]@{ Left=$builtProvider; Right=(Join-Path $testOutput 'GraphKit.Auth.dll'); Kind='tested provider' }
                [pscustomobject]@{ Left=$builtProvider; Right=(Join-Path $providerPublish 'GraphKit.Auth.dll'); Kind='published provider' }
                [pscustomobject]@{ Left=$builtContracts; Right=(Join-Path $testOutput 'GraphKit.Auth.Contracts.dll'); Kind='tested contracts' }
                [pscustomobject]@{ Left=$builtProviderDeps; Right=(Join-Path $providerPublish 'GraphKit.Auth.deps.json'); Kind='published dependency graph' }
                [pscustomobject]@{ Left=(Join-Path $testOutput 'Microsoft.Identity.Client.dll'); Right=(Join-Path $providerPublish 'Microsoft.Identity.Client.dll'); Kind='tested MSAL' }
                [pscustomobject]@{ Left=(Join-Path $testOutput 'Microsoft.IdentityModel.Abstractions.dll'); Right=(Join-Path $providerPublish 'Microsoft.IdentityModel.Abstractions.dll'); Kind='tested IdentityModel' }
            )
            foreach ($pair in $lineagePairs) {
                $leftHash = (Get-FileHash -LiteralPath $pair.Left -Algorithm SHA256).Hash
                $rightHash = (Get-FileHash -LiteralPath $pair.Right -Algorithm SHA256).Hash
                if ($leftHash -cne $rightHash) { throw "The GraphKit.Auth $($pair.Kind) bytes do not share one Release lineage." }
            }
            $identities = [ordered]@{
                'GraphKit.Auth.Contracts.dll' = 'GraphKit.Auth.Contracts, Version=1.0.0.0'
                'GraphKit.Auth.dll' = 'GraphKit.Auth, Version=1.0.0.0'
                'Microsoft.Identity.Client.dll' = 'Microsoft.Identity.Client, Version=4.82.1.0'
                'Microsoft.IdentityModel.Abstractions.dll' = 'Microsoft.IdentityModel.Abstractions, Version=8.14.0.0'
            }
            foreach ($pair in $identities.GetEnumerator()) {
                $path = if ($pair.Key -ceq 'GraphKit.Auth.Contracts.dll') { $builtContracts } else { Join-Path $providerPublish $pair.Key }
                $identity = [Reflection.AssemblyName]::GetAssemblyName($path)
                $actual = "$($identity.Name), Version=$($identity.Version)"
                if ($actual -cne $pair.Value) { throw "Unexpected managed identity for '$($pair.Key)': '$actual'." }
            }
            $contractsInspectionContext = [Runtime.Loader.AssemblyLoadContext]::new(
                "GraphKit.Auth.Contracts.BuildInspection.$runId", $true)
            try {
                $contractsAssembly = $contractsInspectionContext.LoadFromAssemblyPath($builtContracts)
                $forbiddenReferences = @($contractsAssembly.GetReferencedAssemblies() | Where-Object {
                    $_.Name -eq 'GraphKit.Auth' -or $_.Name -like 'Microsoft.Identity*'
                })
                if ($forbiddenReferences.Count -ne 0) {
                    throw "GraphKit.Auth.Contracts has a forbidden runtime reference: $($forbiddenReferences.Name -join ', ')."
                }
            }
            finally {
                $contractsAssembly = $null
                $contractsInspectionContext.Unload()
                $contractsInspectionContext = $null
            }
            $null = [IO.Directory]::CreateDirectory($payloadSource)
            foreach ($name in $script:GraphKitAuthProviderFiles) {
                $null = $script:GraphKitAuthStageCaptureType::CopyFileCreateNew($providerPublish, $name, $payloadSource, $name)
            }
            $contractsRoot = Split-Path $builtContracts -Parent
            $null = $script:GraphKitAuthStageCaptureType::CopyFileCreateNew($contractsRoot, 'GraphKit.Auth.Contracts.dll', $payloadSource, 'GraphKit.Auth.Contracts.dll')
            $quarantine = Invoke-GraphKitAuthLiteralQuarantine -RepositoryRoot $BuildRoot
            $script:GraphKitAuthQuarantine = $quarantine
            Write-Host "GraphKit.Auth generated roots quarantined at '$quarantine'."
            $version = & (Join-Path $BuildRoot 'scripts/Get-GraphKitTrainVersion.ps1') -RepositoryRoot $BuildRoot -AsObject
            $script:GraphKitAuthStage = New-GraphKitAuthSealedStage -OutputRoot (Join-Path $BuildRoot 'output') -FullVersion $version.version -PayloadSourceRoot $payloadSource
        }
        catch {
            $primaryFailure = $_
            throw
        }
        finally {
            if ($null -eq $quarantine) {
                try {
                    $quarantine = Invoke-GraphKitAuthLiteralQuarantine -RepositoryRoot $BuildRoot
                    $script:GraphKitAuthQuarantine = $quarantine
                    Write-Host "GraphKit.Auth generated roots quarantined at '$quarantine'."
                }
                catch {
                    if ($null -eq $primaryFailure) { throw }
                    Write-Warning 'GraphKit.Auth generated-root quarantine also failed; the earlier build failure remains authoritative.'
                }
            }
        }
    }

    task Copy_GraphKitAuth_Into_BuiltModule {
        . Set-SamplerTaskVariable
        if ($null -eq $script:GraphKitAuthStage) { throw 'The current build has no sealed GraphKit.Auth stage.' }
        $verified = Test-GraphKitAuthSealedStage -StagePath $script:GraphKitAuthStage.StagePath -FullVersion $script:GraphKitAuthStage.FullVersion
        $destination = Join-Path $BuiltModuleBase 'Assemblies/GraphKit.Auth'
        if (Test-Path -LiteralPath $destination) { throw "GraphKit.Auth built-module destination '$destination' already exists." }
        $null = [IO.Directory]::CreateDirectory($destination)
        foreach ($record in @($verified.Manifest.files)) {
            $name = [IO.Path]::GetFileName([string]$record.path)
            $copy = $script:GraphKitAuthStageCaptureType::CopyFileCreateNew($verified.PayloadPath, $name, $destination, $name)
            if ([string]$copy.Destination.Sha256 -cne [string]$record.sha256 -or $copy.Destination.LinkCount -ne 1) {
                throw "GraphKit.Auth built-module copy validation failed for '$name'."
            }
        }
        Assert-GraphKitAuthExactDirectoryClosure -Directory $destination -ExpectedNames $script:GraphKitAuthPayloadFiles -Kind 'built-module payload'
        $manifestPath = Join-Path $BuiltModuleBase 'GraphKit.psd1'
        $manifestText = [IO.File]::ReadAllText($manifestPath)
        if ($manifestText -notmatch '(?m)^\s*RequiredAssemblies\s*=\s*@\(\)\s*$') {
            throw 'The built GraphKit manifest no longer has the expected empty RequiredAssemblies literal.'
        }
        $updated = [regex]::Replace($manifestText, '(?m)^(\s*RequiredAssemblies\s*=\s*)@\(\)(\s*)$', "`$1@('Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll')`$2", 1)
        [IO.File]::WriteAllText($manifestPath, $updated, [Text.UTF8Encoding]::new($false))
        $moduleManifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
        if ((@($moduleManifest.RequiredAssemblies | ForEach-Object { $_.ToString() }) -join '|') -cne 'Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll') {
            throw 'The built GraphKit manifest RequiredAssemblies value is not exact.'
        }
    }

    task Pester_Tests_With_GraphKitAuth_ABI_Fixture {
        $pesterExitCode = $null
        try {
            $script:GraphKitAuthAbiTestFixture = New-GraphKitAuthAbiTestFixture `
                -RepositoryRoot $BuildRoot -OutputRoot (Join-Path $BuildRoot 'output')
            $pwshPath = [Environment]::ProcessPath
            & $pwshPath -NoLogo -NoProfile -File (Join-Path $BuildRoot 'build.ps1') `
                -Tasks Pester_Tests_Stop_On_Fail
            $pesterExitCode = $LASTEXITCODE
        }
        finally {
            Remove-GraphKitAuthAbiTestFixture -RepositoryRoot $BuildRoot
        }
        if ($pesterExitCode -ne 0) {
            throw "The guarded GraphKit.Auth ABI Pester run failed with exit code '$pesterExitCode'."
        }
    }
}
