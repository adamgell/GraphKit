BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $script:built = Get-ChildItem (Join-Path $script:repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $script:built) {
        throw 'No built GraphKit module found under output/module/GraphKit; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $script:built.FullName 'GraphKit.psd1') -Force

    function New-TestSecretManagementModule {
        param(
            [Parameter(Mandatory)] [string] $Root,
            [Parameter(Mandatory)] [version] $Version
        )

        $moduleRoot = Join-Path $Root "Microsoft.PowerShell.SecretManagement/$Version"
        $null = New-Item -ItemType Directory -Path $moduleRoot -Force
        $rootModule = Join-Path $moduleRoot 'Microsoft.PowerShell.SecretManagement.psm1'
        @'
function Get-SecretVault {
    [CmdletBinding()]
    param([string] $Name)
    [pscustomobject]@{ Name = $Name; ModuleName = 'Synthetic.SecretStore' }
}

function Get-Secret {
    [CmdletBinding()]
    param([string] $Name, [string] $Vault)
    $value = [System.Security.SecureString]::new()
    foreach ($character in 'synthetic-value'.ToCharArray()) { $value.AppendChar($character) }
    return $value
}

Export-ModuleMember -Function Get-SecretVault, Get-Secret
'@ | Set-Content -LiteralPath $rootModule -Encoding utf8

        New-ModuleManifest -Path (Join-Path $moduleRoot 'Microsoft.PowerShell.SecretManagement.psd1') `
            -RootModule 'Microsoft.PowerShell.SecretManagement.psm1' -ModuleVersion $Version `
            -FunctionsToExport @('Get-SecretVault', 'Get-Secret')
        return $Root
    }
}

Describe 'lazy SecretManagement boundary' {
    BeforeEach {
        $script:savedModulePath = $env:PSModulePath
        $script:previousSecretModules = @(Get-Module Microsoft.PowerShell.SecretManagement)
        InModuleScope GraphKit {
            Remove-Module Microsoft.PowerShell.SecretManagement -Force -ErrorAction SilentlyContinue
        }
        Remove-Module Microsoft.PowerShell.SecretManagement -Force -ErrorAction SilentlyContinue
        $script:foreignVaultCalls = 0
        $script:foreignSecretCalls = 0
        function global:Get-SecretVault {
            $script:foreignVaultCalls++
            [pscustomobject]@{ Name = 'v'; ModuleName = 'Foreign.Module' }
        }
        function global:Get-Secret {
            $script:foreignSecretCalls++
            ConvertTo-SecureString 'foreign-value' -AsPlainText -Force
        }
    }

    AfterEach {
        InModuleScope GraphKit {
            Remove-Module Microsoft.PowerShell.SecretManagement -Force -ErrorAction SilentlyContinue
        }
        Remove-Module Microsoft.PowerShell.SecretManagement -Force -ErrorAction SilentlyContinue
        Remove-Item Function:\Get-SecretVault, Function:\Get-Secret -Force -ErrorAction SilentlyContinue
        $env:PSModulePath = $script:savedModulePath
        foreach ($module in $script:previousSecretModules) {
            Import-Module $module.Path -Force -ErrorAction SilentlyContinue
        }
    }

    It 'imports a discoverable SecretManagement 1.1.2 or newer and bypasses same-named foreign functions' {
        $modulePath = New-TestSecretManagementModule -Root (Join-Path $TestDrive 'valid') -Version '9.9.9'
        $env:PSModulePath = $modulePath

        $result = InModuleScope GraphKit {
            Get-GraphVaultCredential -Credential @{ VaultName = 'v'; SecretName = 'client-secret' } -AuthMethod ClientSecret
        }

        [System.Net.NetworkCredential]::new('', $result.Material).Password | Should -Be 'synthetic-value'
        InModuleScope GraphKit {
            (Get-Module Microsoft.PowerShell.SecretManagement).Version | Should -Be ([version] '9.9.9')
        }
        $script:foreignVaultCalls | Should -Be 0
        $script:foreignSecretCalls | Should -Be 0
    }

    It 'rejects an installed SecretManagement older than 1.1.2 before any foreign command can run' {
        $modulePath = New-TestSecretManagementModule -Root (Join-Path $TestDrive 'old') -Version '1.1.1'
        $env:PSModulePath = $modulePath

        {
            InModuleScope GraphKit {
                Get-GraphVaultCredential -Credential @{ VaultName = 'v'; SecretName = 'client-secret' } -AuthMethod ClientSecret
            }
        } | Should -Throw -ExpectedMessage '*Microsoft.PowerShell.SecretManagement*1.1.2*1.1.1*'

        $script:foreignVaultCalls | Should -Be 0
        $script:foreignSecretCalls | Should -Be 0
    }

    It 'rejects same-named foreign functions when SecretManagement is unavailable' {
        $emptyModulePath = Join-Path $TestDrive 'empty'
        $null = New-Item -ItemType Directory -Path $emptyModulePath -Force
        $env:PSModulePath = $emptyModulePath

        {
            InModuleScope GraphKit {
                Get-GraphVaultCredential -Credential @{ VaultName = 'v'; SecretName = 'client-secret' } -AuthMethod ClientSecret
            }
        } | Should -Throw -ExpectedMessage '*Microsoft.PowerShell.SecretManagement*Install-Module*1.1.2*'

        $script:foreignVaultCalls | Should -Be 0
        $script:foreignSecretCalls | Should -Be 0
    }
}
