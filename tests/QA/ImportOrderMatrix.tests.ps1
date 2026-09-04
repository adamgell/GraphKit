<#
    Phase 1.6 gate: the MSAL import-order matrix.

    Microsoft.Identity.Client is a private implementation detail of
    Microsoft.Graph.Authentication, and in the default .NET load context the first
    copy loaded into the process wins for every consumer. This matrix imports
    GraphKit's dependencies in each meaningful order, in a FRESH pwsh process per
    row, and asserts that the import-time guard still passes and records which MSAL
    version actually won. A silent version change is otherwise indistinguishable
    from a working configuration until a customer engagement.

    Run:  ./build.ps1 -Tasks build   then   Invoke-Pester ./tests/QA/ImportOrderMatrix.tests.ps1
#>

BeforeDiscovery {
    $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:BuiltBase = Get-ChildItem -Path (Join-Path $repoRoot 'output/module/GraphKit') -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    $script:AzAvailable = [bool](Get-Module Az.Accounts -ListAvailable -ErrorAction SilentlyContinue)

    $matrixRows = @(
        @{ Name = 'GraphKit-first';      PreModules = @();                                             IsAz = $false }
        @{ Name = 'PSResourceGet-first'; PreModules = @('Microsoft.PowerShell.PSResourceGet');         IsAz = $false }
        @{ Name = 'GraphAuth-first';     PreModules = @('Microsoft.Graph.Authentication');             IsAz = $false }
    )
    if ($script:AzAvailable) {
        $matrixRows += @{ Name = 'AzAccounts-first'; PreModules = @('Az.Accounts'); IsAz = $true }
    }
}

Describe 'MSAL import-order matrix' -Skip:($null -eq $script:BuiltBase) {

    BeforeAll {
        $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        $script:BuiltBase = Get-ChildItem -Path (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
            Sort-Object Name -Descending | Select-Object -First 1
        $script:manifestPath = Join-Path $script:BuiltBase.FullName 'GraphKit.psd1'
        $script:AzAvailable = [bool](Get-Module Az.Accounts -ListAvailable -ErrorAction SilentlyContinue)

        $script:MatrixRows = @(
            @{ Name = 'GraphKit-first';      PreModules = @();                                             IsAz = $false }
            @{ Name = 'PSResourceGet-first'; PreModules = @('Microsoft.PowerShell.PSResourceGet');         IsAz = $false }
            @{ Name = 'GraphAuth-first';     PreModules = @('Microsoft.Graph.Authentication');             IsAz = $false }
        )
        if ($script:AzAvailable) {
            $script:MatrixRows += @{ Name = 'AzAccounts-first'; PreModules = @('Az.Accounts'); IsAz = $true }
        }

        function Invoke-GraphImportOrderProbe {
            param(
                [string] $ManifestPath,
                [string[]] $PreModules
            )

            $imports = ($PreModules | ForEach-Object { "    Import-Module '$_' -ErrorAction Stop" }) -join "`n"

            $childTemplate = @'
$ErrorActionPreference = 'Stop'
$result = [ordered]@{
    ImportSucceeded     = $true
    GuardOutcome        = 'passed'
    GuardError          = $null
    DetectedMsalVersion = $null
}
try {
__IMPORTS__
    Import-Module '__MANIFEST__' -ErrorAction Stop
}
catch {
    $result.ImportSucceeded = $false
    $result.GuardOutcome = 'failed'
    $result.GuardError = $_.Exception.Message
}
$msal = [AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GetName().Name -eq 'Microsoft.Identity.Client' } |
    Select-Object -First 1
if ($msal) { $result.DetectedMsalVersion = $msal.GetName().Version.ToString() }
[pscustomobject] $result | ConvertTo-Json -Compress
'@

            $escapedManifest = $ManifestPath.Replace("'", "''")
            $child = $childTemplate.Replace('__IMPORTS__', $imports).Replace('__MANIFEST__', $escapedManifest)

            $output = & pwsh -NoProfile -Command $child 2>&1 | ForEach-Object { $_.ToString() }
            $jsonLine = $output | Where-Object { $_.StartsWith('{"ImportSucceeded"') } | Select-Object -Last 1

            if (-not $jsonLine) {
                throw "import-order probe produced no JSON report. Raw output:`n$($output -join "`n")"
            }

            return $jsonLine | ConvertFrom-Json
        }

        # One fresh child process per row; each is bounded well under 60 seconds.
        $script:Results = @{}
        foreach ($row in $script:MatrixRows) {
            $script:Results[$row.Name] = Invoke-GraphImportOrderProbe -ManifestPath $script:manifestPath -PreModules $row.PreModules
        }
    }

    It 'row <Name> imports GraphKit successfully (guard passed)' -ForEach $matrixRows {
        $result = $script:Results[$_.Name]
        $result.ImportSucceeded | Should -BeTrue -Because "guard error: $($result.GuardError)"
        $result.GuardOutcome | Should -Be 'passed'
    }

    It 'row <Name> detects a MSAL version at or above the tested minimum' -ForEach $matrixRows {
        $version = $script:Results[$_.Name].DetectedMsalVersion
        $version | Should -Not -BeNullOrEmpty
        ([version] $version) -ge [version] '4.82.1' | Should -BeTrue -Because "detected MSAL $version is below the tested minimum 4.82.1"
    }

    It 'the bundled MSAL has not changed MAJOR version' -ForEach $matrixRows {
        # The design defers GraphKit.Auth - the compiled adapter in an isolated
        # AssemblyLoadContext - as "much later, not v1", and names the conditions that would bring
        # it forward. One is "Microsoft.Graph.Authentication changing or removing its bundled
        # MSAL". Removal is already caught: the import guard fails outright. A DOWNGRADE is caught
        # by the minimum below. An UPGRADE was not caught by anything - MSAL 5.x would satisfy
        # ">= 4.82.1" and sail through, which is the one shape of that trigger that arrives
        # silently.
        #
        # This turns the prose trigger into an executable one. A major-version change is not
        # necessarily a failure of GraphKit; it is a signal that the deferral needs re-deciding by
        # a person, which is exactly what a red test asks for.
        $version = [version] $script:Results[$_.Name].DetectedMsalVersion
        $version.Major | Should -Be 4 -Because @'
the bundled Microsoft.Identity.Client changed major version. This is a RECORDED TRIGGER for
bringing GraphKit.Auth forward (see the design spec: "Microsoft.Graph.Authentication changing or
removing its bundled MSAL"). Re-decide the deferral rather than raising this number reflexively.
'@
    }

    It 'all non-Az rows agree on a single winning MSAL version' {
        $winners = @($script:MatrixRows | Where-Object { -not $_.IsAz } | ForEach-Object { $script:Results[$_.Name].DetectedMsalVersion } | Select-Object -Unique)
        $winners.Count | Should -Be 1 -Because "non-Az rows surfaced different winners: $($winners -join ', ')"
    }

    It 'Az.Accounts row stays within the tested minimum (a different winner warns, not fails)' -Skip:(-not $script:AzAvailable) {
        $azRow = $script:MatrixRows | Where-Object { $_.IsAz } | Select-Object -First 1
        $azVersion = $script:Results[$azRow.Name].DetectedMsalVersion
        ([version] $azVersion) -ge [version] '4.82.1' | Should -BeTrue

        $baseline = @($script:MatrixRows | Where-Object { -not $_.IsAz } | ForEach-Object { $script:Results[$_.Name].DetectedMsalVersion } | Select-Object -Unique)
        if ($azVersion -notin $baseline) {
            Write-Warning "Az.Accounts loaded MSAL $azVersion, a different winner from the non-Az baseline ($($baseline -join ', ')). The guard still passed; this divergence is exactly what the import-order matrix exists to surface."
        }
    }
}

Describe 'Import-order without SecretManagement' -Skip:($null -eq $script:BuiltBase) {
    BeforeAll {
        $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        $built = Get-ChildItem -Path (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
            Sort-Object Name -Descending | Select-Object -First 1
        $graphAuth = Join-Path $repoRoot 'output/RequiredModules/Microsoft.Graph.Authentication/2.38.1'
        if (-not (Test-Path -LiteralPath $graphAuth -PathType Container)) {
            throw 'Microsoft.Graph.Authentication 2.38.1 is not available for the isolated import-order probe.'
        }

        $modulePath = Join-Path $TestDrive 'import-order-no-vault'
        $graphKitDestination = Join-Path $modulePath "GraphKit/$($built.Name)"
        $graphAuthDestination = Join-Path $modulePath 'Microsoft.Graph.Authentication/2.38.1'
        $null = New-Item -ItemType Directory -Path $graphKitDestination, $graphAuthDestination -Force
        Copy-Item -Path (Join-Path $built.FullName '*') -Destination $graphKitDestination -Recurse -Force
        Copy-Item -Path (Join-Path $graphAuth '*') -Destination $graphAuthDestination -Recurse -Force

        $escapedModulePath = $modulePath.Replace("'", "''")
        $escapedManifest = (Join-Path $graphKitDestination 'GraphKit.psd1').Replace("'", "''")
        $probe = @"
`$ErrorActionPreference = 'Stop'
`$result = [ordered]@{
    ImportSucceeded           = `$false
    GuardError                = `$null
    DetectedMsalVersion       = `$null
    SecretManagementLoaded    = `$false
    SecretManagementAvailable = `$false
    OperationName             = `$null
}
try {
    `$env:PSModulePath = '$escapedModulePath'
    Import-Module '$escapedManifest' -ErrorAction Stop
    `$result.ImportSucceeded = `$true
    `$operation = Get-GraphOperation -Type ManagedDevice -Operation List
    `$result.OperationName = "`$(`$operation.Type).`$(`$operation.Operation)"
}
catch {
    `$result.GuardError = `$_.Exception.Message
}
`$msal = [AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { `$_.GetName().Name -eq 'Microsoft.Identity.Client' } |
    Select-Object -First 1
if (`$msal) { `$result.DetectedMsalVersion = `$msal.GetName().Version.ToString() }
`$result.SecretManagementLoaded = [bool] (Get-Module Microsoft.PowerShell.SecretManagement)
`$env:PSModulePath = '$escapedModulePath'
`$result.SecretManagementAvailable = [bool] (Get-Module Microsoft.PowerShell.SecretManagement -ListAvailable -Refresh)
[pscustomobject] `$result | ConvertTo-Json -Compress
"@

        $savedModulePath = $env:PSModulePath
        try {
            $env:PSModulePath = $modulePath
            $raw = & pwsh -NoLogo -NoProfile -Command $probe 2>&1
        }
        finally {
            $env:PSModulePath = $savedModulePath
        }

        $json = @($raw | Where-Object { $_ -is [string] -and $_.TrimStart().StartsWith('{') }) | Select-Object -Last 1
        if (-not $json) {
            throw "isolated import-order probe produced no JSON. Raw output:`n$($raw | Out-String)"
        }
        $script:NoVaultImport = $json | ConvertFrom-Json
    }

    It 'imports GraphKit and inspects the catalog without SecretManagement on PSModulePath' {
        $script:NoVaultImport.ImportSucceeded | Should -BeTrue -Because $script:NoVaultImport.GuardError
        $script:NoVaultImport.GuardError | Should -BeNullOrEmpty
        $script:NoVaultImport.OperationName | Should -Be 'ManagedDevice.List'
        $script:NoVaultImport.SecretManagementLoaded | Should -BeFalse
        $script:NoVaultImport.SecretManagementAvailable | Should -BeFalse
    }

    It 'still loads a tested MSAL version when SecretManagement is absent' {
        $version = $script:NoVaultImport.DetectedMsalVersion
        $version | Should -Not -BeNullOrEmpty
        ([version] $version) -ge [version] '4.82.1' | Should -BeTrue
        ([version] $version).Major | Should -Be 4
    }
}
