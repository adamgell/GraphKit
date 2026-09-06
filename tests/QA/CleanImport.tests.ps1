BeforeAll {
    # Importing the built module must leave the session's error stream EMPTY.
    #
    # This exists because a defect escaped every other gate here. The module-load guard used
    # `Get-Command -Name X -ErrorAction SilentlyContinue` to test whether a function existed.
    # SilentlyContinue suppresses the *display* of an error, not the record: Get-Command still
    # wrote a CommandNotFoundException into $Error. The guard was false on every normal import,
    # so GraphKit dirtied $Error every single time it loaded. Nothing threw, nothing failed, and
    # 630 tests stayed green - it was found by an external reviewer importing a consumer module.
    #
    # Two things about how it is asserted matter:
    #
    #   - `Should -Not -Throw` would pass. A non-terminating error is not an exception. Asserting
    #     the absence of an exception says nothing about the error stream, and that gap is
    #     exactly how this survived.
    #   - `Import-Module -ErrorVariable ev` does NOT capture it either. -ErrorVariable collects
    #     errors from the Import-Module cmdlet itself, not errors recorded while the module body
    #     executes. Only $Error sees those.
    #
    # So the check runs in a CLEAN pwsh - this session has already imported GraphKit and has a
    # populated $Error - clears $Error, imports, and reports what is left.
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $built = Get-ChildItem -Path (Join-Path $script:repoRoot 'output/module/GraphKit') -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) {
        throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first.'
    }
    $script:manifestPath = Join-Path $built.FullName 'GraphKit.psd1'

    function Invoke-CleanImportProbe {
        param([string] $ImportStatement)

        $probe = @"
`$ErrorActionPreference = 'Continue'
`$Error.Clear()
$ImportStatement
[pscustomobject]@{
    ErrorCount = `$Error.Count
    Errors     = @(`$Error | ForEach-Object {
        '{0}: {1} (at {2}:{3})' -f `$_.Exception.GetType().Name,
                                   (`$_.Exception.Message -replace '\s+', ' '),
                                   (Split-Path `$_.InvocationInfo.ScriptName -Leaf),
                                   `$_.InvocationInfo.ScriptLineNumber
    })
    Commands   = @(Get-Command -Module GraphKit).Count
} | ConvertTo-Json -Depth 4 -Compress
"@
        $raw = & pwsh -NoProfile -Command $probe 2>&1
        $json = @($raw | Where-Object { $_ -is [string] -and $_.TrimStart().StartsWith('{') }) | Select-Object -Last 1
        if (-not $json) { throw "Probe produced no result. Output was:`n$($raw -join "`n")" }
        return $json | ConvertFrom-Json
    }
}

Describe 'Built module imports cleanly' {

    It 'writes nothing to the error stream when imported by path' {
        $result = Invoke-CleanImportProbe "Import-Module '$script:manifestPath' -Force"

        # -Because carries the diagnosis: the failure text is otherwise just a number.
        $result.ErrorCount | Should -Be 0 -Because "importing GraphKit must leave `$Error empty; got: $($result.Errors -join ' | ')"
        $result.Commands | Should -BeGreaterThan 0
    }

    It 'writes nothing to the error stream when imported by name' {
        # The path a consumer actually takes: resolution through PSModulePath.
        $installed = Get-Module GraphKit -ListAvailable | Select-Object -First 1
        if ($null -eq $installed) {
            Set-ItResult -Skipped -Because 'GraphKit is not installed on PSModulePath; the by-path case above still covers module-body load errors'
            return
        }

        $result = Invoke-CleanImportProbe 'Import-Module GraphKit -Force'
        $result.ErrorCount | Should -Be 0 -Because "importing GraphKit by name must leave `$Error empty; got: $($result.Errors -join ' | ')"
    }

    It 'writes nothing to the error stream when imported twice' {
        # A re-import re-runs the module body, so any load-time error is emitted again.
        $result = Invoke-CleanImportProbe "Import-Module '$script:manifestPath' -Force; Import-Module '$script:manifestPath' -Force"
        $result.ErrorCount | Should -Be 0 -Because "re-importing must also leave `$Error empty; got: $($result.Errors -join ' | ')"
    }

    It 'registers its handler strategies despite the import-time guard being false' {
        # The guard this test was written for is false on a normal import, by design: the
        # registry is concatenated after this file. Registration therefore happens lazily on
        # first use, and that path must work - otherwise silencing the error would hide a
        # module that cannot resolve any strategy.
        $probe = @"
Import-Module '$script:manifestPath' -Force
& (Get-Module GraphKit) {
    Ensure-GraphV1StrategiesRegistered
    @(`$script:GraphHandlerStrategyRegistry.Keys).Count
}
"@
        $count = & pwsh -NoProfile -Command $probe 2>&1 | Select-Object -Last 1
        [int] $count | Should -Be 5 -Because 'all five v1 strategies must register: Collection, Singleton, Action, Reconciliation, LongRunningJob'
    }
}

Describe 'Non-vault GraphKit paths do not require SecretManagement or a vault' {
    BeforeAll {
        $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
        $built = Get-ChildItem -Path (Join-Path $script:repoRoot 'output/module/GraphKit') -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | Select-Object -First 1
        if ($null -eq $built) {
            throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first.'
        }

        $graphAuth = Join-Path $script:repoRoot 'output/RequiredModules/Microsoft.Graph.Authentication/2.38.1'
        if (-not (Test-Path -LiteralPath $graphAuth -PathType Container)) {
            throw 'Microsoft.Graph.Authentication 2.38.1 is not available for the isolated non-vault probe.'
        }

        $modulePath = Join-Path $TestDrive 'non-vault-modules'
        $graphKitDestination = Join-Path $modulePath "GraphKit/$($built.Name)"
        $graphAuthDestination = Join-Path $modulePath 'Microsoft.Graph.Authentication/2.38.1'
        $null = New-Item -ItemType Directory -Path $graphKitDestination, $graphAuthDestination -Force
        Copy-Item -Path (Join-Path $built.FullName '*') -Destination $graphKitDestination -Recurse -Force
        Copy-Item -Path (Join-Path $graphAuth '*') -Destination $graphAuthDestination -Recurse -Force

        $isolatedManifest = Join-Path $graphKitDestination 'GraphKit.psd1'
        $storePath = Join-Path $TestDrive 'non-vault-profiles.json'
        $escapedModulePath = $modulePath.Replace("'", "''")
        $escapedManifest = $isolatedManifest.Replace("'", "''")
        $escapedStore = $storePath.Replace("'", "''")

        $probe = @"
`$ErrorActionPreference = 'Stop'
`$result = [ordered]@{
    ImportSucceeded                   = `$false
    FatalStage                        = `$null
    FatalError                        = `$null
    HelpName                          = `$null
    OperationName                     = `$null
    MiAuthMode                        = `$null
    MiIdentityState                   = `$null
    InjectedAuthMode                  = `$null
    ClientSecretContextError          = `$null
    BearerContextError                = `$null
    SecretManagementLoadedAfterImport = `$false
    SecretManagementLoadedAtEnd       = `$false
    SecretManagementAvailableAtEnd    = `$false
}
`$stage = 'import'
try {
    `$env:PSModulePath = '$escapedModulePath'
    Import-Module '$escapedManifest' -Force -ErrorAction Stop
    `$result.ImportSucceeded = `$true
    `$result.SecretManagementLoadedAfterImport = [bool] (Get-Module Microsoft.PowerShell.SecretManagement)

    # RequiredModule resolution may re-add the host's default module roots. Reset the
    # path and loaded-module table before exercising the optional dependency boundary.
    `$env:PSModulePath = '$escapedModulePath'
    Remove-Module Microsoft.PowerShell.SecretManagement -Force -ErrorAction SilentlyContinue

    `$stage = 'help-and-catalog'
    `$help = Get-Help Get-GraphOperation -ErrorAction Stop
    `$operation = Get-GraphOperation -Type ManagedDevice -Operation List
    `$result.HelpName = [string] `$help.Name
    `$result.OperationName = "`$(`$operation.Type).`$(`$operation.Operation)"

    `$stage = 'managed-identity'
    Register-GraphTenant -ProfileId 'mi-lab' -Name 'Lab' -Kind lab ``
        -TenantId '3a4b5c6d-1111-2222-3333-444455556666' -Environment Global ``
        -AuthMethod ManagedIdentity -StorePath '$escapedStore'
    `$miContext = Get-GraphContext -ProfileId 'mi-lab' -StorePath '$escapedStore'
    `$result.MiAuthMode = [string] `$miContext.TokenSource.AuthMode
    `$result.MiIdentityState = [string] `$miContext.IdentityState

    `$stage = 'injected-provider'
    Register-GraphTenant -ProfileId 'provider-lab' -Name 'Provider' -Kind lab ``
        -TenantId '3a4b5c6d-1111-2222-3333-444455556666' ``
        -ClientId '7d6e5f44-9999-8888-7777-666655554444' -Environment Global ``
        -AuthMethod ClientSecret -VaultName 'missing' -SecretName 'client-secret' ``
        -StorePath '$escapedStore'
    `$injected = Get-GraphContext -ProfileId 'provider-lab' -StorePath '$escapedStore' ``
        -TokenProvider { @{ Token = 'injected-token'; ExpiresOnUtc = [datetime]::UtcNow.AddHours(1) } }
    `$result.InjectedAuthMode = [string] `$injected.TokenSource.AuthMode

    `$stage = 'client-secret-boundary'
    try {
        `$null = Get-GraphContext -ProfileId 'provider-lab' -StorePath '$escapedStore'
    }
    catch {
        `$result.ClientSecretContextError = @(`$_.Exception.Message, `$_.Exception.InnerException.Message, (`$_ | Out-String)) -join ' '
    }

    `$stage = 'bearer-boundary'
    Register-GraphTenant -ProfileId 'bearer-lab' -Name 'Bearer' -Kind lab ``
        -TenantId '3a4b5c6d-1111-2222-3333-444455556666' -Environment Global ``
        -AuthMethod BearerToken -VaultName 'missing' -SecretName 'bearer' ``
        -StorePath '$escapedStore'
    try {
        `$null = Get-GraphContext -ProfileId 'bearer-lab' -StorePath '$escapedStore'
    }
    catch {
        `$result.BearerContextError = @(`$_.Exception.Message, `$_.Exception.InnerException.Message, (`$_ | Out-String)) -join ' '
    }
}
catch {
    `$result.FatalStage = `$stage
    `$result.FatalError = @(`$_.Exception.Message, `$_.Exception.InnerException.Message, (`$_ | Out-String)) -join ' '
}
finally {
    `$result.SecretManagementLoadedAtEnd = [bool] (Get-Module Microsoft.PowerShell.SecretManagement)
    `$env:PSModulePath = '$escapedModulePath'
    `$result.SecretManagementAvailableAtEnd = [bool] (Get-Module Microsoft.PowerShell.SecretManagement -ListAvailable -Refresh)
}
[pscustomobject] `$result | ConvertTo-Json -Compress
"@

        $savedModulePath = $env:PSModulePath
        try {
            # Set this before creating pwsh so its initial discovery cache cannot see
            # the developer machine's optional SecretManagement installation.
            $env:PSModulePath = $modulePath
            $raw = & pwsh -NoLogo -NoProfile -Command $probe 2>&1
            $exitCode = $LASTEXITCODE
        }
        finally {
            $env:PSModulePath = $savedModulePath
        }

        $json = @($raw | Where-Object { $_ -is [string] -and $_.TrimStart().StartsWith('{') }) | Select-Object -Last 1
        $script:isolated = [pscustomobject]@{
            ExitCode = $exitCode
            Data     = if ($json) { $json | ConvertFrom-Json } else { $null }
            Output   = ($raw | Out-String).Trim()
        }
    }

    It 'imports help and catalog inspection without SecretManagement' {
        $script:isolated.ExitCode | Should -Be 0 -Because $script:isolated.Output
        $script:isolated.Data | Should -Not -BeNullOrEmpty -Because $script:isolated.Output
        $script:isolated.Data.ImportSucceeded | Should -BeTrue -Because "stage $($script:isolated.Data.FatalStage): $($script:isolated.Data.FatalError)"
        $script:isolated.Data.FatalError | Should -BeNullOrEmpty
        $script:isolated.Data.HelpName | Should -Be 'Get-GraphOperation'
        $script:isolated.Data.OperationName | Should -Be 'ManagedDevice.List'
        $script:isolated.Data.SecretManagementLoadedAfterImport | Should -BeFalse
        $script:isolated.Data.SecretManagementLoadedAtEnd | Should -BeFalse
        $script:isolated.Data.SecretManagementAvailableAtEnd | Should -BeFalse
    }

    It 'registers and resolves managed identity without SecretManagement' {
        $script:isolated.Data.MiAuthMode | Should -Be 'ManagedIdentity'
        $script:isolated.Data.MiIdentityState | Should -Be 'NotAcquired'
    }

    It 'resolves an injected token provider without SecretManagement' {
        $script:isolated.Data.InjectedAuthMode | Should -Be 'Provider'
    }

    It 'fails a vault-backed client-secret profile actionably at context resolution' {
        $script:isolated.Data.ClientSecretContextError | Should -Match 'Microsoft\.PowerShell\.SecretManagement'
        $script:isolated.Data.ClientSecretContextError | Should -Match 'Install-Module'
        $script:isolated.Data.ClientSecretContextError | Should -Match '1\.1\.2'
    }

    It 'fails a vault-backed bearer profile with the missing-module message, not an opaque token error' {
        $script:isolated.Data.BearerContextError | Should -Match 'Microsoft\.PowerShell\.SecretManagement'
        $script:isolated.Data.BearerContextError | Should -Match 'Install-Module'
        $script:isolated.Data.BearerContextError | Should -Not -Match '(?i)token.*(invalid|expired|malformed)'
    }
}
