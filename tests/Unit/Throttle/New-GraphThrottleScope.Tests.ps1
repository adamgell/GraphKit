BeforeAll {
    $repoRoot = (Join-Path $PSScriptRoot '../../..') | Convert-Path

    # Import the built module: it owns every private function and registers the
    # GraphThrottleCoordinator C# type exactly once, so tests never dot-source
    # source/ files or define types in test scope.
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) {
        throw 'No built GraphKit module found under output/module/GraphKit. Run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force
}

Describe 'New-GraphThrottleScope' {

    It 'computes the coarse and leaf keys from context and descriptor' {
        InModuleScope GraphKit {
            $context = [pscustomobject]@{
                Cloud    = 'Global'
                TenantId = [guid] '00000000-0000-0000-0000-000000000001'
                ClientId = [guid] '11111111-1111-1111-1111-111111111111'
            }
            $descriptor = @{
                ThrottleClass  = 'Read'
                ResourceFamily = 'Intune.ManagedDevices'
            }

            $scope = New-GraphThrottleScope -Context $context -Descriptor $descriptor

            $scope.CoarseKey | Should -Be 'Global|00000000-0000-0000-0000-000000000001|11111111-1111-1111-1111-111111111111|Read'
            $scope.LeafKey | Should -Be 'Global|00000000-0000-0000-0000-000000000001|11111111-1111-1111-1111-111111111111|Read|Intune.ManagedDevices'
            $scope.ThrottleClass | Should -Be 'Read'
            $scope.ResourceFamily | Should -Be 'Intune.ManagedDevices'
            $scope.Cloud | Should -Be 'Global'
            $scope.TenantId | Should -Be '00000000-0000-0000-0000-000000000001'
            $scope.ClientId | Should -Be '11111111-1111-1111-1111-111111111111'
        }
    }

    It 'normalizes tenant and client ids to lowercase invariant GUIDs' {
        InModuleScope GraphKit {
            $context = [pscustomobject]@{
                Cloud    = 'Global'
                TenantId = 'ABCDEF01-2345-6789-ABCD-EF0123456789'
                ClientId = [guid] 'FEDCBA98-7654-3210-FEDC-BA9876543210'
            }
            $descriptor = @{
                ThrottleClass  = 'Write'
                ResourceFamily = 'Intune.Reporting'
            }

            $scope = New-GraphThrottleScope -Context $context -Descriptor $descriptor

            $scope.TenantId | Should -Be 'abcdef01-2345-6789-abcd-ef0123456789'
            $scope.ClientId | Should -Be 'fedcba98-7654-3210-fedc-ba9876543210'
            $scope.CoarseKey | Should -Be 'Global|abcdef01-2345-6789-abcd-ef0123456789|fedcba98-7654-3210-fedc-ba9876543210|Write'
            $scope.LeafKey | Should -Be 'Global|abcdef01-2345-6789-abcd-ef0123456789|fedcba98-7654-3210-fedc-ba9876543210|Write|Intune.Reporting'
        }
    }

    It 'is null-safe for a missing client id' {
        InModuleScope GraphKit {
            $context = [pscustomobject]@{
                Cloud    = 'Global'
                TenantId = [guid] '01234567-89ab-cdef-0123-456789abcdef'
                ClientId = $null
            }
            $descriptor = @{
                ThrottleClass  = 'Read'
                ResourceFamily = 'Intune.ManagedDevices'
            }

            $scope = New-GraphThrottleScope -Context $context -Descriptor $descriptor

            $scope.ClientId | Should -Be ''
            $scope.CoarseKey | Should -Be 'Global|01234567-89ab-cdef-0123-456789abcdef||Read'
            $scope.LeafKey | Should -Be 'Global|01234567-89ab-cdef-0123-456789abcdef||Read|Intune.ManagedDevices'
        }
    }

    It 'defaults a non-Write throttle class to Read' {
        InModuleScope GraphKit {
            $context = [pscustomobject]@{
                Cloud    = 'Global'
                TenantId = [guid] '01234567-89ab-cdef-0123-456789abcdef'
                ClientId = [guid] '11111111-1111-1111-1111-111111111111'
            }
            $descriptor = @{
                ThrottleClass  = 'Whatever'
                ResourceFamily = 'Intune.ManagedDevices'
            }

            $scope = New-GraphThrottleScope -Context $context -Descriptor $descriptor

            $scope.ThrottleClass | Should -Be 'Read'
            $scope.CoarseKey | Should -Match '\|Read$'
        }
    }

    It 'builds the token acquisition scope key from authority, resource, and auth mode' {
        InModuleScope GraphKit {
            $context = [pscustomobject]@{
                Cloud    = 'Global'
                TenantId = [guid] '01234567-89ab-cdef-0123-456789abcdef'
                ClientId = [guid] '11111111-1111-1111-1111-111111111111'
            }

            $scope = New-GraphThrottleScope -Acquisition -Context $context `
                -Authority 'https://login.microsoftonline.com/contoso.onmicrosoft.com' `
                -Resource 'https://graph.microsoft.com/.default' `
                -AuthMode 'ClientSecret'

            $scope.CoarseKey | Should -Be 'https://login.microsoftonline.com/contoso.onmicrosoft.com|https://graph.microsoft.com/.default|ClientSecret'
            $scope.LeafKey | Should -Be $scope.CoarseKey
            $scope.ThrottleClass | Should -Be $null
        }
    }
}
