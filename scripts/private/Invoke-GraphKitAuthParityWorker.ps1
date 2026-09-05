<#
    Private child-process boundary for Invoke-GraphKitAuthParity.ps1.
    The parent owns extraction and deletion; this process alone loads the candidate module.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$runnerPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../Invoke-GraphKitAuthParity.ps1'))
$hookKey = 'GraphKit.Task8.ParityTestHooks/1'
$savedHooks = [AppDomain]::CurrentDomain.GetData($hookKey)
[AppDomain]::CurrentDomain.SetData($hookKey, $null)
try {
    . $runnerPath -PackagePath 'unused.nupkg' -PackageSha256 ('0' * 64) `
        -AuthMode Certificate -DryRun
}
finally {
    [AppDomain]::CurrentDomain.SetData($hookKey, $savedHooks)
}
$workerHooks = Get-GraphKitAuthParityTestHooks
Initialize-GraphKitAuthParityProcessTreeNative
$script:GraphKitAuthParityProcessTreeType::EnterUnixWorkerSession()

function New-GraphKitAuthParityInternalResult {
    param(
        [string] $Nonce = $('0' * 64),
        [string] $Execution = 'DryRun',
        [string] $Mode = 'Certificate',
        [string] $Digest = $('0' * 64),
        [string] $ModuleVersion = '0.0.0-rejected',
        [string] $RequestSha256 = $('0' * 64)
    )
    $adapter = [ordered]@{}
    foreach ($name in $script:GraphKitAuthParityAdapterChecks) { $adapter[$name] = $false }
    return [pscustomobject][ordered]@{
        recordKind = $script:GraphKitAuthParityWorkerResultKind
        nonce = $Nonce
        requestSha256 = $RequestSha256
        execution = $Execution
        authMode = $Mode
        packageSha256 = $Digest
        moduleVersion = $ModuleVersion
        state = 'Failed'
        failureStage = 'Import'
        failureCode = 'ImportRejected'
        exactImport = $false
        adapter = [pscustomobject]$adapter
        contextMatched = $false
        sourceMatched = $false
        tenantProofVerified = $false
        readAttempted = $false
        readSucceeded = $false
        rowCount = [long]0
        workerTeardownVerified = $false
    }
}

function Read-GraphKitAuthParityInternalRequest {
    $inputStream = [Console]::OpenStandardInput()
    $memory = [IO.MemoryStream]::new()
    $buffer = [byte[]]::new(4096)
    try {
        while (($count = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            if ($memory.Length + $count -gt $script:GraphKitAuthParityMaxWorkerRequestBytes) {
                throw [InvalidOperationException]::new(
                    'The protected parity worker request exceeded its byte bound.')
            }
            $memory.Write($buffer, 0, $count)
        }
        if ($memory.Length -eq 0) {
            throw [InvalidOperationException]::new(
                'The protected parity worker request is invalid.')
        }
        return ,$memory.ToArray()
    }
    finally {
        $memory.Dispose()
        $inputStream.Dispose()
    }
}

$result = New-GraphKitAuthParityInternalResult
$request = $null
$state = $null
$route = $null
$imported = $null
$importedModule = $null
$diagnostics = $null
$providerWeakReference = $null
$liveCore = $null
$failureStage = 'Import'
$failureCode = 'ImportRejected'
$cleanupFailed = $false
$hadModulePath = Test-Path -LiteralPath Env:PSModulePath
$savedModulePath = if ($hadModulePath) { [string]$env:PSModulePath } else { $null }
$modulePathChanged = $false

try {
    [byte[]]$requestBytes = Read-GraphKitAuthParityInternalRequest
    $requestSha256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($requestBytes)).ToLowerInvariant()
    $requestText = [Text.UTF8Encoding]::new($false, $true).GetString($requestBytes)
    if ($requestText -cnotmatch '\A\{[^\r\n]*\}\z' -or
        $requestText[0] -eq [char]0xFEFF) {
        throw [InvalidOperationException]::new('The protected parity worker request frame is invalid.')
    }
    $request = ConvertFrom-GraphKitAuthParityWorkerJson -Json $requestText `
        -MaximumBytes $script:GraphKitAuthParityMaxWorkerRequestBytes
    $converted = ConvertFrom-GraphKitAuthParityWorkerState -Request $request
    $state = $converted.State
    if ([string]$request.nonce -cnotmatch '^[0-9a-f]{64}$') {
        throw [InvalidOperationException]::new('The protected parity worker nonce was rejected.')
    }
    $result = New-GraphKitAuthParityInternalResult -Nonce ([string]$request.nonce) `
        -Execution ([string]$request.execution) -Mode ([string]$request.authMode) `
        -Digest ([string]$request.packageSha256) `
        -ModuleVersion ([string]$request.moduleVersion) -RequestSha256 $requestSha256
    if (@(Get-Module -Name GraphKit -All).Count -ne 0) {
        throw [InvalidOperationException]::new('A GraphKit module is already loaded in the worker.')
    }

    Initialize-GraphKitAuthParityNative
    Assert-GraphKitAuthParityState -State $state -Purpose Import
    $route = Get-GraphKitAuthParityDescriptorRoute `
        -ManifestRoot $state.ModuleRoot -Mode ([string]$request.authMode)
    if ((Get-GraphKitAuthParityFullVersion -ManifestPath $state.ExtractedManifestPath) -cne
        [string]$request.moduleVersion) {
        throw [InvalidOperationException]::new('The protected parity worker version was rejected.')
    }

    $env:PSModulePath = if ($hadModulePath -and
        -not [string]::IsNullOrEmpty($savedModulePath)) {
        $state.ModuleRoot + [IO.Path]::PathSeparator + $savedModulePath
    }
    else { $state.ModuleRoot }
    $modulePathChanged = $true
    Assert-GraphKitAuthParityState -State $state -Purpose Import
    $imported = Invoke-GraphKitAuthParityCaptured -ExpectedCount 1 -Action {
        Import-Module -Name $state.ExtractedManifestPath -PassThru -Force -ErrorAction Stop
    }
    $importedModule = $imported[0]
    $comparison = if ($IsWindows) {
        [StringComparison]::OrdinalIgnoreCase
    }
    else { [StringComparison]::Ordinal }
    if ($importedModule.Name -cne 'GraphKit' -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath($importedModule.ModuleBase),
            [IO.Path]::GetFullPath($state.ModuleRoot), $comparison) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath($importedModule.Path),
            [IO.Path]::GetFullPath($state.ExtractedModulePath), $comparison) -or
        "$($importedModule.Version)-$($importedModule.PrivateData.PSData.Prerelease)" -cne
            [string]$request.moduleVersion) {
        throw [InvalidOperationException]::new('The exact extracted GraphKit module was not imported.')
    }
    $state.ImportedManifestPath = $state.ExtractedManifestPath
    $state.ImportedModulePath = $importedModule.Path
    $result.exactImport = $true
    Invoke-GraphKitAuthParityHook -Hooks $workerHooks -Name AfterImport -Arguments @($state)

    $failureStage = 'Diagnostics'
    $failureCode = 'DiagnosticsRejected'
    $diagnostics = Get-GraphKitAuthParityDiagnostics -Module $importedModule -State $state
    $providerWeakReference = $diagnostics.ProviderWeakReference
    foreach ($property in $diagnostics.Checks.PSObject.Properties) {
        $result.adapter.$($property.Name) = [bool]$property.Value
    }
    if (@($result.adapter.PSObject.Properties.Value | Where-Object { -not [bool]$_ }).Count -ne 0) {
        throw [InvalidOperationException]::new('The GraphKit.Auth adapter diagnostics were rejected.')
    }

    if ($request.execution -ceq 'Live') {
        $storePathBound = [bool]$request.storePathBound
        Invoke-GraphKitAuthParityHook -Hooks $workerHooks -Name PrepareLiveModule `
            -Arguments @(
                $importedModule, $state, $route, [string]$request.profileId,
                $(if ($storePathBound) { [string]$request.storePath } else { $null }),
                $storePathBound)
        Assert-GraphKitAuthParityState -State $state -Purpose Import
        $contextCommands = @(Get-Command -Name Get-GraphContext -Module GraphKit `
            -CommandType Function -ErrorAction Stop)
        $readCommands = @(Get-Command -Name Get-GraphObject -Module GraphKit `
            -CommandType Function -ErrorAction Stop)
        if ($contextCommands.Count -ne 1 -or
            -not [object]::ReferenceEquals($contextCommands[0].Module, $importedModule) -or
            $readCommands.Count -ne 1 -or
            -not [object]::ReferenceEquals($readCommands[0].Module, $importedModule)) {
            throw [InvalidOperationException]::new('The exact public live commands were not found.')
        }
        $getContextAction = {
            param($requestedProfileId, $requestedStorePath, $selectedRoute)
            $parameters = @{ ProfileId = $requestedProfileId; ErrorAction = 'Stop' }
            if ($storePathBound) { $parameters.StorePath = $requestedStorePath }
            $records = Invoke-GraphKitAuthParityCaptured -ExpectedCount 1 -Action {
                & $contextCommands[0] @parameters
            }
            return $records[0]
        }.GetNewClosure()
        $readAction = {
            param($context, $type, $operation, $passThruResult)
            $records = Invoke-GraphKitAuthParityCaptured -ExpectedCount 1 -Action {
                & $readCommands[0] -Context $context -Type $type -Operation $operation `
                    -PassThruResult:$passThruResult -ErrorAction Stop
            }
            return $records[0]
        }.GetNewClosure()
        $liveCore = Invoke-GraphKitAuthParityLiveCore -Route $route -Diagnostics $diagnostics `
            -ProfileId ([string]$request.profileId) -StorePath ([string]$request.storePath) `
            -StorePathBound:$storePathBound -GetContextAction $getContextAction `
            -ReadAction $readAction
        $result.contextMatched = [bool]$liveCore.contextMatched
        $result.sourceMatched = [bool]$liveCore.sourceMatched
        $result.tenantProofVerified = [bool]$liveCore.tenantProofVerified
        $result.readAttempted = [bool]$liveCore.readAttempted
        $result.readSucceeded = [bool]$liveCore.readSucceeded
        $result.rowCount = [long]$liveCore.rowCount
        if ($liveCore.state -cne 'Passed') {
            $failureStage = [string]$liveCore.failureStage
            $failureCode = [string]$liveCore.failureCode
            throw [InvalidOperationException]::new('The protected parity live core was rejected.')
        }
    }
    $result.state = 'Passed'
    $result.failureStage = 'None'
    $result.failureCode = 'None'
}
catch {
    $result.state = 'Failed'
    $result.failureStage = $failureStage
    $result.failureCode = $failureCode
}
finally {
    $liveCore = $null
    $route = $null
    $diagnostics = $null
    $imported = $null
    if ($null -ne $importedModule) {
        try {
            $null = Invoke-GraphKitAuthParityCaptured -ExpectedCount 0 -Action {
                Remove-Module -ModuleInfo $importedModule -Force -ErrorAction Stop
            }
        }
        catch { $cleanupFailed = $true }
        $importedModule = $null
    }
    # The provider context was proven collectible by diagnostics and by its
    # dedicated unload gate. Process exit is the isolation boundary here; a
    # script-scope local can otherwise retain the WeakReference target until exit.
    $providerWeakReference = $null
    if ($modulePathChanged) {
        if ($hadModulePath) { $env:PSModulePath = $savedModulePath }
        else { Remove-Item -LiteralPath Env:PSModulePath -ErrorAction SilentlyContinue }
    }
    $result.workerTeardownVerified = -not $cleanupFailed
    if ($cleanupFailed) {
        $result.state = 'Failed'
        $result.failureStage = 'Cleanup'
        $result.failureCode = 'CleanupFailed'
    }
}

$json = $result | ConvertTo-Json -Compress -Depth 5
[Console]::Out.WriteLine($json)
