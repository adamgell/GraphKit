BeforeAll {
    $repoRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $built = Get-ChildItem -Path (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) {
        throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first, then re-run the tests.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force

    function New-TestCertificate {
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        try {
            $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=GraphKit lifecycle test',
                $rsa,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            return $request.CreateSelfSigned(
                [System.DateTimeOffset]::UtcNow.AddMinutes(-1),
                [System.DateTimeOffset]::UtcNow.AddMinutes(10)
            )
        }
        finally {
            $rsa.Dispose()
        }
    }
}

Describe 'New-GraphMsalApplicationFactory ownership and generation' {

    It 'registers an owned certificate only after a successful application build' {
        $certificate = New-TestCertificate
        $registrations = [System.Collections.Generic.List[object]]::new()
        try {
            $result = InModuleScope GraphKit -Parameters @{
                Certificate = $certificate
                Registrations = $registrations
            } {
                param($Certificate, $Registrations)

                $application = [pscustomobject] @{ Name = 'built-application' }
                $state = [pscustomobject] @{
                    Certificate = $null
                    Authority   = $null
                    Application = $application
                }
                $builder = [pscustomobject] @{ State = $state }
                $builder | Add-Member ScriptMethod WithCertificate {
                    param($Value)
                    $this.State.Certificate = $Value
                    return $this
                }
                $builder | Add-Member ScriptMethod WithAuthority {
                    param($Value)
                    $this.State.Authority = $Value
                    return $this
                }
                $builder | Add-Member ScriptMethod Build { return $this.State.Application }

                $factory = New-GraphMsalApplicationFactory `
                    -Profile @{
                        TenantId = '00000000-0000-0000-0000-000000000001'
                        ClientId = '00000000-0000-0000-0000-000000000002'
                        AuthMethod = 'Certificate'
                        Credential = @{}
                    } `
                    -Cloud @{ Authority = 'https://login.microsoftonline.com' } `
                    -ExpectedCredentialGeneration 'generation-1|context:0123456789abcdef0123456789abcdef' `
                    -CredentialResolver {
                        param($Profile)
                        $null = $Profile
                        [pscustomobject] @{
                            Material = $Certificate
                            OwnsMaterial = $true
                            CredentialGeneration = 'generation-1'
                        }
                    }.GetNewClosure() `
                    -ApplicationBuilderFactory { param($ClientId) $null = $ClientId; $builder }.GetNewClosure() `
                    -OwnedResourceRegistrar {
                        param($Resource, [bool] $OwnedByGraphKit)
                        $Registrations.Add([pscustomobject] @{
                            Resource = $Resource
                            Owned = $OwnedByGraphKit
                        })
                        # Match the default registrar's convenience return so
                        # the factory proves that ownership-transfer output is
                        # never mixed with its application result.
                        return $Resource
                    }.GetNewClosure()

                [pscustomobject] @{
                    Application = (& $factory)
                    BuilderState = $state
                }
            }

            @($result.Application).Count | Should -Be 1
            [object]::ReferenceEquals($result.Application, $result.BuilderState.Application) | Should -BeTrue
            [object]::ReferenceEquals($result.BuilderState.Certificate, $certificate) | Should -BeTrue
            $registrations.Count | Should -Be 1
            [object]::ReferenceEquals($registrations[0].Resource, $certificate) | Should -BeTrue
            $registrations[0].Owned | Should -BeTrue
            $certificate.Handle | Should -Not -Be ([IntPtr]::Zero)
        }
        finally {
            $certificate.Dispose()
        }
    }

    It 'never registers or disposes caller-owned certificate material' {
        $certificate = New-TestCertificate
        $registrations = [System.Collections.Generic.List[object]]::new()
        try {
            $null = InModuleScope GraphKit -Parameters @{
                Certificate = $certificate
                Registrations = $registrations
            } {
                param($Certificate, $Registrations)

                $builder = [pscustomobject] @{ Application = [pscustomobject] @{ Name = 'external' } }
                $builder | Add-Member ScriptMethod WithCertificate { param($Value) $null = $Value; return $this }
                $builder | Add-Member ScriptMethod WithAuthority { param($Value) $null = $Value; return $this }
                $builder | Add-Member ScriptMethod Build { return $this.Application }

                $factory = New-GraphMsalApplicationFactory `
                    -Profile @{
                        TenantId = '00000000-0000-0000-0000-000000000001'
                        ClientId = '00000000-0000-0000-0000-000000000002'
                        AuthMethod = 'Certificate'
                        Credential = @{}
                    } `
                    -Cloud @{ Authority = 'https://login.microsoftonline.com' } `
                    -ExpectedCredentialGeneration 'generation-1' `
                    -CredentialResolver {
                        param($Profile)
                        $null = $Profile
                        [pscustomobject] @{
                            Material = $Certificate
                            OwnsMaterial = $false
                            CredentialGeneration = 'generation-1'
                        }
                    }.GetNewClosure() `
                    -ApplicationBuilderFactory { param($ClientId) $null = $ClientId; $builder }.GetNewClosure() `
                    -OwnedResourceRegistrar {
                        param($Resource, [bool] $OwnedByGraphKit)
                        $Registrations.Add([pscustomobject] @{ Resource = $Resource; Owned = $OwnedByGraphKit })
                    }.GetNewClosure()

                & $factory
            }

            $registrations.Count | Should -Be 0
            $certificate.Handle | Should -Not -Be ([IntPtr]::Zero)
            $certificate.HasPrivateKey | Should -BeTrue
        }
        finally {
            $certificate.Dispose()
        }
    }

    It 'disposes owned material and rejects a generation changed after context creation' {
        $certificate = New-TestCertificate
        $buildCalls = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()

        {
            InModuleScope GraphKit -Parameters @{
                Certificate = $certificate
                BuildCalls = $buildCalls
            } {
                param($Certificate, $BuildCalls)

                $factory = New-GraphMsalApplicationFactory `
                    -Profile @{
                        TenantId = '00000000-0000-0000-0000-000000000001'
                        ClientId = '00000000-0000-0000-0000-000000000002'
                        AuthMethod = 'Certificate'
                        Credential = @{}
                    } `
                    -Cloud @{ Authority = 'https://login.microsoftonline.com' } `
                    -ExpectedCredentialGeneration 'old-generation' `
                    -CredentialResolver {
                        param($Profile)
                        $null = $Profile
                        [pscustomobject] @{
                            Material = $Certificate
                            OwnsMaterial = $true
                            CredentialGeneration = 'new-generation'
                        }
                    }.GetNewClosure() `
                    -ApplicationBuilderFactory {
                        param($ClientId)
                        $null = $ClientId
                        $BuildCalls.Enqueue('builder-created')
                        throw 'builder must not be reached'
                    }.GetNewClosure() `
                    -OwnedResourceRegistrar { throw 'registration must not be reached' }

                & $factory
            }
        } | Should -Throw -ExpectedMessage '*changed after this context was created*Create a new GraphKit context*'

        $buildCalls.Count | Should -Be 0
        $certificate.Handle | Should -Be ([IntPtr]::Zero)
    }

    It 'rejects missing material generation before builder creation and disposes the owned secret' {
        $secret = [System.Security.SecureString]::new()
        $secret.AppendChar('x')
        $buildCalls = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()

        {
            InModuleScope GraphKit -Parameters @{ Secret = $secret; BuildCalls = $buildCalls } {
                param($Secret, $BuildCalls)
                $factory = New-GraphMsalApplicationFactory `
                    -Profile @{
                        TenantId = '00000000-0000-0000-0000-000000000001'
                        ClientId = '00000000-0000-0000-0000-000000000002'
                        AuthMethod = 'ClientSecret'
                        Credential = @{}
                    } `
                    -Cloud @{ Authority = 'https://login.microsoftonline.com' } `
                    -ExpectedCredentialGeneration 'expected-generation' `
                    -CredentialResolver {
                        [pscustomobject] @{
                            Material = $Secret
                            OwnsMaterial = $true
                        }
                    }.GetNewClosure() `
                    -ApplicationBuilderFactory {
                        $BuildCalls.Enqueue('builder-created')
                        throw 'builder must not be reached'
                    }.GetNewClosure()

                & $factory
            }
        } | Should -Throw -ExpectedMessage '*did not report the generation*identity cannot be verified*'

        $buildCalls.Count | Should -Be 0
        {
            $pointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        } | Should -Throw -ExpectedMessage '*disposed object*SecureString*'
    }

    It 'accepts an isolated unversioned ClientSecret generation and disposes its owned copy after build' {
        $secret = [System.Security.SecureString]::new()
        foreach ($ch in 'client-secret'.ToCharArray()) { $secret.AppendChar($ch) }

        $result = InModuleScope GraphKit -Parameters @{ Secret = $secret } {
            param($Secret)
            $application = [pscustomobject] @{ Name = 'client-secret-application' }
            $state = [pscustomobject] @{ Secret = $null; Authority = $null; Application = $application }
            $builder = [pscustomobject] @{ State = $state }
            $builder | Add-Member ScriptMethod WithClientSecret {
                param($Value)
                $this.State.Secret = $Value
                return $this
            }
            $builder | Add-Member ScriptMethod WithAuthority {
                param($Value)
                $this.State.Authority = $Value
                return $this
            }
            $builder | Add-Member ScriptMethod Build { return $this.State.Application }

            $factory = New-GraphMsalApplicationFactory `
                -Profile @{
                    TenantId = '00000000-0000-0000-0000-000000000001'
                    ClientId = '00000000-0000-0000-0000-000000000002'
                    AuthMethod = 'ClientSecret'
                    Credential = @{}
                } `
                -Cloud @{ Authority = 'https://login.microsoftonline.com' } `
                -ExpectedCredentialGeneration 'base-generation|context:0123456789abcdef0123456789abcdef' `
                -CredentialResolver {
                    [pscustomobject] @{
                        Material = $Secret
                        OwnsMaterial = $true
                        CredentialGeneration = 'base-generation'
                    }
                }.GetNewClosure() `
                -ApplicationBuilderFactory { $builder }.GetNewClosure()

            [pscustomobject] @{
                Application = (& $factory)
                State = $state
            }
        }

        $result.Application.Name | Should -Be 'client-secret-application'
        $result.State.Secret | Should -Be 'client-secret'
        {
            $pointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        } | Should -Throw -ExpectedMessage '*disposed object*SecureString*'
    }

    It 'disposes owned certificate material when the application builder factory throws' {
        $certificate = New-TestCertificate

        {
            InModuleScope GraphKit -Parameters @{ Certificate = $certificate } {
                param($Certificate)
                $factory = New-GraphMsalApplicationFactory `
                    -Profile @{
                        TenantId = '00000000-0000-0000-0000-000000000001'
                        ClientId = '00000000-0000-0000-0000-000000000002'
                        AuthMethod = 'Certificate'
                        Credential = @{}
                    } `
                    -Cloud @{ Authority = 'https://login.microsoftonline.com' } `
                    -ExpectedCredentialGeneration 'generation-1' `
                    -CredentialResolver {
                        [pscustomobject] @{
                            Material = $Certificate
                            OwnsMaterial = $true
                            CredentialGeneration = 'generation-1'
                        }
                    }.GetNewClosure() `
                    -ApplicationBuilderFactory { throw 'builder-factory-certificate-sentinel' }

                & $factory
            }
        } | Should -Throw -ExpectedMessage '*builder-factory-certificate-sentinel*'

        $certificate.Handle | Should -Be ([IntPtr]::Zero)
    }

    It 'disposes owned ClientSecret material when the application builder factory throws' {
        $secret = [System.Security.SecureString]::new()
        $secret.AppendChar('x')

        {
            InModuleScope GraphKit -Parameters @{ Secret = $secret } {
                param($Secret)
                $factory = New-GraphMsalApplicationFactory `
                    -Profile @{
                        TenantId = '00000000-0000-0000-0000-000000000001'
                        ClientId = '00000000-0000-0000-0000-000000000002'
                        AuthMethod = 'ClientSecret'
                        Credential = @{}
                    } `
                    -Cloud @{ Authority = 'https://login.microsoftonline.com' } `
                    -ExpectedCredentialGeneration 'generation-1' `
                    -CredentialResolver {
                        [pscustomobject] @{
                            Material = $Secret
                            OwnsMaterial = $true
                            CredentialGeneration = 'generation-1'
                        }
                    }.GetNewClosure() `
                    -ApplicationBuilderFactory { throw 'builder-factory-secret-sentinel' }

                & $factory
            }
        } | Should -Throw -ExpectedMessage '*builder-factory-secret-sentinel*'

        {
            $pointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        } | Should -Throw -ExpectedMessage '*disposed object*SecureString*'
    }

    It 'disposes owned certificate material when application construction fails' {
        $certificate = New-TestCertificate

        {
            InModuleScope GraphKit -Parameters @{ Certificate = $certificate } {
                param($Certificate)

                $builder = [pscustomobject] @{}
                $builder | Add-Member ScriptMethod WithCertificate { param($Value) $null = $Value; return $this }
                $builder | Add-Member ScriptMethod WithAuthority { param($Value) $null = $Value; return $this }
                $builder | Add-Member ScriptMethod Build { throw 'build-failure-sentinel' }

                $factory = New-GraphMsalApplicationFactory `
                    -Profile @{
                        TenantId = '00000000-0000-0000-0000-000000000001'
                        ClientId = '00000000-0000-0000-0000-000000000002'
                        AuthMethod = 'Certificate'
                        Credential = @{}
                    } `
                    -Cloud @{ Authority = 'https://login.microsoftonline.com' } `
                    -ExpectedCredentialGeneration 'generation-1' `
                    -CredentialResolver {
                        param($Profile)
                        $null = $Profile
                        [pscustomobject] @{
                            Material = $Certificate
                            OwnsMaterial = $true
                            CredentialGeneration = 'generation-1'
                        }
                    }.GetNewClosure() `
                    -ApplicationBuilderFactory { param($ClientId) $null = $ClientId; $builder }.GetNewClosure() `
                    -OwnedResourceRegistrar { throw 'registration must not be reached' }

                & $factory
            }
        } | Should -Throw -ExpectedMessage '*build-failure-sentinel*'

        $certificate.Handle | Should -Be ([IntPtr]::Zero)
    }
}
