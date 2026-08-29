BeforeAll {
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:sourceManifest = Import-PowerShellDataFile -Path (Join-Path $script:repoRoot 'source/GraphKit.psd1')
    $script:version = [string] $script:sourceManifest.ModuleVersion
    $script:packagePath = Join-Path $script:repoRoot "output/GraphKit.$script:version.nupkg"
    $script:builtModulePath = Join-Path $script:repoRoot "output/module/GraphKit/$script:version"
    $script:graphAuthPath = Join-Path $script:repoRoot 'output/RequiredModules/Microsoft.Graph.Authentication/2.38.1'

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
        $graphKitDestination = Join-Path $modulePath "GraphKit/$script:version"
        $graphAuthDestination = Join-Path $modulePath 'Microsoft.Graph.Authentication/2.38.1'
        $null = New-Item -ItemType Directory -Path $graphKitDestination, $graphAuthDestination -Force
        Copy-Item -Path (Join-Path $script:builtModulePath '*') -Destination $graphKitDestination -Recurse -Force
        Copy-Item -Path (Join-Path $script:graphAuthPath '*') -Destination $graphAuthDestination -Recurse -Force
        return $modulePath
    }

    function Invoke-IsolatedGraphKitProbe {
        param([Parameter(Mandatory)] [string] $ModulePath)

        $isolatedManifest = Join-Path $ModulePath "GraphKit/$script:version/GraphKit.psd1"
        $probe = @"
`$ErrorActionPreference = 'Stop'
Import-Module '$($isolatedManifest.Replace("'", "''"))' -Force -ErrorAction Stop
`$operation = Get-GraphOperation -Type ManagedDevice -Operation List
`$secretManagementLoaded = [bool] (Get-Module Microsoft.PowerShell.SecretManagement)
[pscustomobject]@{
    Imported                  = `$true
    ModuleBase                = (Get-Module GraphKit).ModuleBase
    OperationName             = "`$(`$operation.Type).`$(`$operation.Operation)"
    SecretManagementLoaded    = `$secretManagementLoaded
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
    It 'records Microsoft.Graph.Authentication 2.38.1 as its only NuGet dependency' {
        Test-Path -LiteralPath $script:packagePath -PathType Leaf | Should -BeTrue
        $dependencies = @(Get-PackageDependencies -PackagePath $script:packagePath)

        $dependencies.Count | Should -Be 1
        [string] $dependencies[0].id | Should -Be 'Microsoft.Graph.Authentication'
        [string] $dependencies[0].version | Should -Be '2.38.1'
    }

    It 'imports the isolated artifact and inspects the catalog without loading SecretManagement' {
        $modulePath = New-IsolatedGraphKitModulePath -Root (Join-Path $TestDrive 'non-vault')
        $result = Invoke-IsolatedGraphKitProbe -ModulePath $modulePath

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Data.Imported | Should -BeTrue
        $result.Data.ModuleBase | Should -Be (Join-Path $modulePath "GraphKit/$script:version")
        $result.Data.OperationName | Should -Be 'ManagedDevice.List'
        $result.Data.SecretManagementLoaded | Should -BeFalse -Because 'catalog inspection does not use a vault'
    }

}
