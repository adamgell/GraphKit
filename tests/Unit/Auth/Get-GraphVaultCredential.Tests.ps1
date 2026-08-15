BeforeAll {
    $repoRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $built = Get-ChildItem -Path (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) {
        throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first, then re-run the tests.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force

    # Two self-signed test PFX files (generated once, embedded base64): one with a
    # known password for the PFX-path shape, one without for vault-material shapes.
    $script:PfxBase64 = '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'
    $script:PfxPassword = 'graphkit-test-password'
    $script:PfxBytes = [System.Convert]::FromBase64String($script:PfxBase64)
    $script:PfxPath = Join-Path $TestDrive 'graphkit-test.pfx'
    [System.IO.File]::WriteAllBytes($script:PfxPath, $script:PfxBytes)

    $script:NoPasswordPfxBase64 = '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'
    $script:NoPasswordPfxBytes = [System.Convert]::FromBase64String($script:NoPasswordPfxBase64)

    $script:ClientSecretPlain = 'client-secret-value'
    $script:BearerPlain = 'bearer-token-value'

    $script:SecureSecret = [System.Security.SecureString]::new()
    foreach ($ch in $script:ClientSecretPlain.ToCharArray()) { $script:SecureSecret.AppendChar($ch) }

    $script:SecurePassword = [System.Security.SecureString]::new()
    foreach ($ch in $script:PfxPassword.ToCharArray()) { $script:SecurePassword.AppendChar($ch) }

    $script:BearerSecret = [System.Security.SecureString]::new()
    foreach ($ch in $script:BearerPlain.ToCharArray()) { $script:BearerSecret.AppendChar($ch) }

    function New-TestVault {
        return [pscustomobject]@{ Name = 'v'; ModuleName = 'Microsoft.PowerShell.SecretStore' }
    }

    # Default mocks that throw: a test that unexpectedly reaches a SecretManagement
    # command fails loudly instead of touching a real vault. Vault-backed tests
    # override these; managed identity never reaches them.
    Mock Get-SecretVault -ModuleName GraphKit { throw 'Get-SecretVault must be mocked in this test.' }
    Mock Get-Secret -ModuleName GraphKit { throw 'Get-Secret must be mocked in this test.' }
}

Describe 'Get-GraphVaultCredential' {

    Context 'ClientSecret' {
        It 'resolves a client secret into a SecureString material' {
            Mock Get-SecretVault -ModuleName GraphKit { New-TestVault }
            Mock Get-Secret -ModuleName GraphKit { $script:SecureSecret }

            $result = InModuleScope GraphKit {
                Get-GraphVaultCredential -Credential @{ VaultName = 'v'; SecretName = 'client-secret' } -AuthMethod ClientSecret
            }

            $result.AuthMethod | Should -Be 'ClientSecret'
            $result.Material | Should -BeOfType [System.Security.SecureString]
            [System.Net.NetworkCredential]::new('', $result.Material).Password | Should -Be $script:ClientSecretPlain
            $result.ManagedIdentityClientId | Should -BeNullOrEmpty
            $result.PSTypeNames | Should -Contain 'GraphKit.CredentialMaterial'
            Should-Invoke Get-SecretVault -ModuleName GraphKit -Times 1 -Exactly
            Should-Invoke Get-Secret -ModuleName GraphKit -Times 1 -Exactly
        }

        It 'uses the -VaultName fallback when the credential carries no vault name' {
            $script:RecordedVault = $null
            Mock Get-SecretVault -ModuleName GraphKit { New-TestVault }
            Mock Get-Secret -ModuleName GraphKit {
                $script:RecordedVault = $Vault
                $script:SecureSecret
            }

            InModuleScope GraphKit -Parameters @{ VaultName = 'fallback-vault' } {
                Get-GraphVaultCredential -Credential @{ SecretName = 'client-secret' } -VaultName $VaultName -AuthMethod ClientSecret | Out-Null
            }

            $script:RecordedVault | Should -Be 'fallback-vault'
        }

        It 'fails actionably when the vault is not registered, naming SecretManagement and the remedy' {
            Mock Get-SecretVault -ModuleName GraphKit { return $null }

            {
                InModuleScope GraphKit {
                    Get-GraphVaultCredential -Credential @{ VaultName = 'missing'; SecretName = 'client-secret' } -AuthMethod ClientSecret
                }
            } | Should -Throw -ExpectedMessage '*SecretManagement*Register-SecretVault*'
        }
    }

    Context 'BearerToken' {
        It 'resolves a bearer token into a plain-text string material' {
            Mock Get-SecretVault -ModuleName GraphKit { New-TestVault }
            Mock Get-Secret -ModuleName GraphKit { $script:BearerSecret }

            $result = InModuleScope GraphKit {
                Get-GraphVaultCredential -Credential @{ VaultName = 'v'; SecretName = 'bearer' } -AuthMethod BearerToken
            }

            $result.AuthMethod | Should -Be 'BearerToken'
            $result.Material | Should -BeOfType [string]
            $result.Material | Should -Be $script:BearerPlain
            $result.ManagedIdentityClientId | Should -BeNullOrEmpty
        }
    }

    Context 'Certificate (PFX)' {
        It 'builds an X509Certificate2 from a PFX path and a vault-backed password' {
            Mock Get-SecretVault -ModuleName GraphKit { New-TestVault }
            Mock Get-Secret -ModuleName GraphKit { $script:SecurePassword }

            $result = InModuleScope GraphKit -Parameters @{ Credential = @{
                    PfxPath  = $script:PfxPath
                    Password = @{ VaultName = 'v'; SecretName = 'pfx-password' }
                } } {
                Get-GraphVaultCredential -Credential $Credential -AuthMethod Certificate
            }

            $result.AuthMethod | Should -Be 'Certificate'
            $result.Material | Should -BeOfType [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $result.Material.HasPrivateKey | Should -BeTrue
            $result.ManagedIdentityClientId | Should -BeNullOrEmpty
        }
    }

    Context 'Certificate (vault material)' {
        It 'builds an X509Certificate2 from PFX byte[] material' {
            Mock Get-SecretVault -ModuleName GraphKit { New-TestVault }
            Mock Get-Secret -ModuleName GraphKit { Write-Output -NoEnumerate $script:NoPasswordPfxBytes }

            $result = InModuleScope GraphKit {
                Get-GraphVaultCredential -Credential @{ VaultName = 'v'; CertificateName = 'cert' } -AuthMethod Certificate
            }

            $result.AuthMethod | Should -Be 'Certificate'
            $result.Material | Should -BeOfType [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $result.Material.HasPrivateKey | Should -BeTrue
        }

        It 'builds an X509Certificate2 from base64-encoded PFX material' {
            Mock Get-SecretVault -ModuleName GraphKit { New-TestVault }
            Mock Get-Secret -ModuleName GraphKit { $script:NoPasswordPfxBase64 }

            $result = InModuleScope GraphKit {
                Get-GraphVaultCredential -Credential @{ VaultName = 'v'; CertificateName = 'cert' } -AuthMethod Certificate
            }

            $result.Material | Should -BeOfType [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $result.Material.HasPrivateKey | Should -BeTrue
        }

        It 'fails actionably for unusable certificate material, naming supported shapes' {
            Mock Get-SecretVault -ModuleName GraphKit { New-TestVault }
            Mock Get-Secret -ModuleName GraphKit { 'this is not a certificate' }

            {
                InModuleScope GraphKit {
                    Get-GraphVaultCredential -Credential @{ VaultName = 'v'; CertificateName = 'cert' } -AuthMethod Certificate
                }
            } | Should -Throw -ExpectedMessage '*neither a PFX byte array, a base64-encoded PFX, nor a path to a PFX file*'
        }
    }

    Context 'Certificate (store)' {
        It 'errors as Windows-only on a non-Windows platform' -Skip:$IsWindows {
            {
                InModuleScope GraphKit {
                    Get-GraphVaultCredential -Credential @{ StoreLocation = 'CurrentUser'; StoreName = 'My'; Thumbprint = 'abc123' } -AuthMethod Certificate
                }
            } | Should -Throw -ExpectedMessage '*Windows-only*'
        }
    }

    Context 'ManagedIdentity' {
        It 'returns the user-assigned client id with zero vault calls' {
            $result = InModuleScope GraphKit {
                Get-GraphVaultCredential -Credential @{ ClientId = '7d6e5f44-9999-8888-7777-666655554444' } -AuthMethod ManagedIdentity
            }

            $result.AuthMethod | Should -Be 'ManagedIdentity'
            $result.Material | Should -BeNullOrEmpty
            $result.ManagedIdentityClientId | Should -Be '7d6e5f44-9999-8888-7777-666655554444'
            Should-Invoke Get-SecretVault -ModuleName GraphKit -Times 0 -Exactly
            Should-Invoke Get-Secret -ModuleName GraphKit -Times 0 -Exactly
        }

        It 'returns null for a system-assigned identity with zero vault calls' {
            $result = InModuleScope GraphKit {
                Get-GraphVaultCredential -Credential @{ ClientId = $null } -AuthMethod ManagedIdentity
            }

            $result.AuthMethod | Should -Be 'ManagedIdentity'
            $result.Material | Should -BeNullOrEmpty
            $result.ManagedIdentityClientId | Should -BeNullOrEmpty
            Should-Invoke Get-SecretVault -ModuleName GraphKit -Times 0 -Exactly
            Should-Invoke Get-Secret -ModuleName GraphKit -Times 0 -Exactly
        }
    }
}
