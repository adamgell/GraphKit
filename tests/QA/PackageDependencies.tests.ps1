BeforeAll {
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:sourceManifest = Import-PowerShellDataFile -Path (Join-Path $script:repoRoot 'source/GraphKit.psd1')
    $script:baseVersion = [string] $script:sourceManifest.ModuleVersion
    $script:version = (& (Join-Path $script:repoRoot 'scripts/Get-GraphKitTrainVersion.ps1') -RepositoryRoot $script:repoRoot).Trim()
    $script:packagePath = Join-Path $script:repoRoot "output/GraphKit.$script:version.nupkg"
    $script:graphAuthPath = Join-Path $script:repoRoot 'output/RequiredModules/Microsoft.Graph.Authentication/2.38.1'
    $script:secretManagementPath = Join-Path $script:repoRoot 'output/RequiredModules/Microsoft.PowerShell.SecretManagement/1.1.2'

    function Get-PackageDependencies {
        param([Parameter(Mandatory)] [string] $PackagePath)

        $archive = [System.IO.Compression.ZipFile]::OpenRead($PackagePath)
        try {
            $nuspec = @($archive.Entries | Where-Object { $_.FullName -like '*.nuspec' })
            $nuspec.Count | Should -Be 1
            $reader = [System.IO.StreamReader]::new($nuspec[0].Open())
            try {
                [xml] $xml = $reader.ReadToEnd()
            }
            finally {
                $reader.Dispose()
            }
        }
        finally {
            $archive.Dispose()
        }

        return @($xml.SelectNodes("/*[local-name()='package']/*[local-name()='metadata']/*[local-name()='dependencies']/*[local-name()='dependency']"))
    }

    function New-IsolatedGraphKitModulePath {
        param([Parameter(Mandatory)] [string] $Root)

        $modulePath = Join-Path $Root 'Modules'
        $graphKitDestination = Join-Path $modulePath "GraphKit/$script:baseVersion"
        $graphAuthDestination = Join-Path $modulePath 'Microsoft.Graph.Authentication/2.38.1'
        $secretManagementDestination = Join-Path $modulePath 'Microsoft.PowerShell.SecretManagement/1.1.2'
        $null = New-Item -ItemType Directory -Path $graphKitDestination, $graphAuthDestination, $secretManagementDestination -Force
        [System.IO.Compression.ZipFile]::ExtractToDirectory($script:packagePath, $graphKitDestination)
        Copy-Item -Path (Join-Path $script:graphAuthPath '*') -Destination $graphAuthDestination -Recurse -Force
        Copy-Item -Path (Join-Path $script:secretManagementPath '*') -Destination $secretManagementDestination -Recurse -Force
        return $modulePath
    }

    function Invoke-IsolatedGraphKitProbe {
        param([Parameter(Mandatory)] [string] $ModulePath)

        $isolatedManifest = Join-Path $ModulePath "GraphKit/$script:baseVersion/GraphKit.psd1"
        $probe = @"
`$ErrorActionPreference = 'Stop'
`$env:PSModulePath = '$($ModulePath.Replace("'", "''"))'
Import-Module '$($isolatedManifest.Replace("'", "''"))' -Force -ErrorAction Stop
`$operation = Get-GraphOperation -Type ManagedDevice -Operation List
`$graphAuthenticationLoaded = [bool] (Get-Module Microsoft.Graph.Authentication)
`$secretManagementLoaded = [bool] (Get-Module Microsoft.PowerShell.SecretManagement)
# PowerShell re-adds its default module roots while resolving RequiredModules during import.
# Reset the path after import, then refresh discovery so this is an availability proof rather
# than a check against either the loaded-module table or stale module-analysis cache state.
`$env:PSModulePath = '$($ModulePath.Replace("'", "''"))'
`$graphAuthenticationAvailable = [bool] (Get-Module Microsoft.Graph.Authentication -ListAvailable -Refresh)
`$secretManagementAvailable = [bool] (Get-Module Microsoft.PowerShell.SecretManagement -ListAvailable -Refresh)
[pscustomobject]@{
    Imported                     = `$true
    ModuleBase                   = (Get-Module GraphKit).ModuleBase
    OperationName                = "`$(`$operation.Type).`$(`$operation.Operation)"
    GraphAuthenticationLoaded    = `$graphAuthenticationLoaded
    GraphAuthenticationAvailable = `$graphAuthenticationAvailable
    SecretManagementLoaded       = `$secretManagementLoaded
    SecretManagementAvailable    = `$secretManagementAvailable
} | ConvertTo-Json -Compress
"@

        $savedModulePath = $env:PSModulePath
        try {
            # Set this before creating pwsh so its initial module-analysis cache has no
            # visibility outside the empty install under test.
            $env:PSModulePath = $ModulePath
            $raw = & pwsh -NoLogo -NoProfile -Command $probe 2>&1
            $exitCode = $LASTEXITCODE
        }
        finally {
            $env:PSModulePath = $savedModulePath
        }
        $json = @($raw | Where-Object { $_ -is [string] -and $_.TrimStart().StartsWith('{') }) | Select-Object -Last 1
        $data = if ($json) { $json | ConvertFrom-Json } else { $null }
        return [pscustomobject]@{
            ExitCode = $exitCode
            Data     = $data
            Output   = ($raw | Out-String).Trim()
        }
    }
}

Describe 'Packed GraphKit dependency contract' -Tag 'QA' {
    It 'records Graph Authentication and SecretManagement as exact NuGet dependencies' {
        Test-Path -LiteralPath $script:packagePath -PathType Leaf | Should -BeTrue
        $dependencies = @(Get-PackageDependencies -PackagePath $script:packagePath)

        $dependencies.Count | Should -Be 2
        $dependencyMap = @{}
        foreach ($dependency in $dependencies) { $dependencyMap[[string] $dependency.id] = [string] $dependency.version }
        $dependencyMap['Microsoft.Graph.Authentication'] | Should -Be '2.38.1'
        $dependencyMap['Microsoft.PowerShell.SecretManagement'] | Should -Be '1.1.2'
    }

    It 'imports the isolated artifact with both required runtime dependencies' {
        $modulePath = New-IsolatedGraphKitModulePath -Root (Join-Path $TestDrive 'non-vault')
        $result = Invoke-IsolatedGraphKitProbe -ModulePath $modulePath

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Data.Imported | Should -BeTrue
        $result.Data.ModuleBase | Should -Be (Join-Path $modulePath "GraphKit/$script:baseVersion")
        $result.Data.OperationName | Should -Be 'ManagedDevice.List'
        $result.Data.GraphAuthenticationLoaded | Should -BeTrue -Because 'Graph Authentication remains the R8 transition MSAL delivery vehicle'
        $result.Data.GraphAuthenticationAvailable | Should -BeTrue -Because 'Graph Authentication remains a required runtime package dependency until cutover'
        $result.Data.SecretManagementLoaded | Should -BeTrue -Because 'SecretManagement is restored as a runtime RequiredModule'
        $result.Data.SecretManagementAvailable | Should -BeTrue -Because 'SecretManagement is a required runtime package dependency'
    }

}
