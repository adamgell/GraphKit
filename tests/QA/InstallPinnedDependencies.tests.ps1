BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:installer = Join-Path $script:repoRoot 'scripts/Install-GraphKitPinned.ps1'

    function New-TestPin {
        param(
            [Parameter(Mandatory)] [string] $Root,
            [Parameter(Mandatory)] [string] $Version
        )

        $channel = Join-Path $Root 'channel'
        $null = New-Item -ItemType Directory -Path $channel -Force
        $pinPath = Join-Path $Root "graphkit-$Version.pin.json"
        [ordered]@{
            schema      = 'graphkit-pin/1'
            moduleName  = 'GraphKit'
            version     = $Version
            packageName = "GraphKit.$Version.nupkg"
            sha256      = ('a' * 64)
            channel     = 'FileSystem'
            source      = $channel
        } | ConvertTo-Json | Set-Content -LiteralPath $pinPath -Encoding utf8
        return $pinPath
    }
}

Describe 'Install-GraphKitPinned dependency selection' -Tag 'QA' {
    BeforeEach {
        $global:GraphKitPinnedTestInstalledDependencies = [System.Collections.Generic.List[string]]::new()

        Mock Get-Module -ParameterFilter { $ListAvailable } {
            if ($global:GraphKitPinnedTestInstalledDependencies.Contains([string] $Name)) {
                $version = if ($Name -eq 'Microsoft.Graph.Authentication') { '2.38.1' } else { '1.1.2' }
                return [pscustomobject]@{ Name = $Name; Version = [version] $version; ModuleBase = $TestDrive }
            }
            return @()
        }
        Mock Get-PSResourceRepository { $null }
        Mock Register-PSResourceRepository { }
        Mock Get-InstalledPSResource { $null }
        Mock Install-PSResource {
            if ($Name -eq 'GraphKit') { throw 'stop-after-dependencies' }
            $global:GraphKitPinnedTestInstalledDependencies.Add([string] $Name)
        }
    }

    AfterEach {
        Remove-Variable GraphKitPinnedTestInstalledDependencies -Scope Global -ErrorAction SilentlyContinue
    }

    It 'installs only hard Graph Authentication by default for a next-release package' {
        $pin = New-TestPin -Root (Join-Path $TestDrive 'next-default') -Version '0.3.0'

        { & $script:installer -PinPath $pin -RestoreRecordPath (Join-Path $TestDrive 'next-default/restore.json') } |
            Should -Throw -ExpectedMessage '*stop-after-dependencies*'

        @($global:GraphKitPinnedTestInstalledDependencies) | Should -Be @('Microsoft.Graph.Authentication')
    }

    It 'installs lazy SecretManagement for a next-release package only when explicitly requested' {
        $pin = New-TestPin -Root (Join-Path $TestDrive 'next-vault') -Version '0.3.0'

        { & $script:installer -PinPath $pin -RestoreRecordPath (Join-Path $TestDrive 'next-vault/restore.json') -InstallSecretManagement } |
            Should -Throw -ExpectedMessage '*stop-after-dependencies*'

        @($global:GraphKitPinnedTestInstalledDependencies) | Should -Be @('Microsoft.Graph.Authentication', 'Microsoft.PowerShell.SecretManagement')
    }

    It 'continues installing SecretManagement for immutable GraphKit 0.2.2 because that published package requires it' {
        $pin = New-TestPin -Root (Join-Path $TestDrive 'immutable-022') -Version '0.2.2'

        { & $script:installer -PinPath $pin -RestoreRecordPath (Join-Path $TestDrive 'immutable-022/restore.json') } |
            Should -Throw -ExpectedMessage '*stop-after-dependencies*'

        @($global:GraphKitPinnedTestInstalledDependencies) | Should -Be @('Microsoft.Graph.Authentication', 'Microsoft.PowerShell.SecretManagement')
    }
}
