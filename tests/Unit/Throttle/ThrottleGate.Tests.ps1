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

    $script:utcNow = [datetime] '2026-01-01T00:00:00Z'

    $script:context = [pscustomobject]@{
        Cloud    = 'Global'
        TenantId = [guid] '01234567-89ab-cdef-0123-456789abcdef'
        ClientId = [guid] '11111111-1111-1111-1111-111111111111'
    }
    $script:descriptor = @{
        ThrottleClass  = 'Read'
        ResourceFamily = 'Intune.ManagedDevices'
    }
}

Describe 'Update-GraphThrottleState' {

    It 'updates only the coarse gate on an unqualified 429' {
        InModuleScope GraphKit -Parameters @{
            UtcNow     = $script:utcNow
            Context    = $script:context
            Descriptor = $script:descriptor
        } {
            param($UtcNow, $Context, $Descriptor)

            $coordinator = [GraphThrottleCoordinator]::new()
            $scope = New-GraphThrottleScope -Context $Context -Descriptor $Descriptor

            Update-GraphThrottleState -Scope $scope -Qualified $false -RetryAfterSeconds 30 `
                -StatusCode 429 -Coordinator $coordinator -UtcNow $UtcNow

            $coordinator.GetCooldownUntilUtc($scope.CoarseKey) | Should -Be $UtcNow.AddSeconds(30)
            $coordinator.GetMaxConcurrent($scope.CoarseKey) | Should -Be 8
            $coordinator.ContainsKey($scope.LeafKey) | Should -BeFalse
        }
    }

    It 'updates the leaf gate with a cut on a qualified 503' {
        InModuleScope GraphKit -Parameters @{
            UtcNow     = $script:utcNow
            Context    = $script:context
            Descriptor = $script:descriptor
        } {
            param($UtcNow, $Context, $Descriptor)

            $coordinator = [GraphThrottleCoordinator]::new()
            $scope = New-GraphThrottleScope -Context $Context -Descriptor $Descriptor

            Update-GraphThrottleState -Scope $scope -Qualified $true -RetryAfterSeconds 20 `
                -StatusCode 503 -Coordinator $coordinator -UtcNow $UtcNow

            $coordinator.GetMaxConcurrent($scope.LeafKey) | Should -Be 1
            $coordinator.GetCooldownUntilUtc($scope.LeafKey) | Should -Be $UtcNow.AddSeconds(20)
            $coordinator.ContainsKey($scope.CoarseKey) | Should -BeFalse
        }
    }

    It 'paces (cooldown only) on a 2xx carrying Retry-After' {
        InModuleScope GraphKit -Parameters @{
            UtcNow     = $script:utcNow
            Context    = $script:context
            Descriptor = $script:descriptor
        } {
            param($UtcNow, $Context, $Descriptor)

            $coordinator = [GraphThrottleCoordinator]::new()
            $scope = New-GraphThrottleScope -Context $Context -Descriptor $Descriptor

            Update-GraphThrottleState -Scope $scope -Qualified $false -RetryAfterSeconds 15 `
                -StatusCode 200 -Coordinator $coordinator -UtcNow $UtcNow

            $coordinator.GetCooldownUntilUtc($scope.LeafKey) | Should -Be $UtcNow.AddSeconds(15)
            $coordinator.GetMaxConcurrent($scope.LeafKey) | Should -Be 8
        }
    }

    It 'leaves throttle state untouched for other status codes' {
        InModuleScope GraphKit -Parameters @{
            UtcNow     = $script:utcNow
            Context    = $script:context
            Descriptor = $script:descriptor
        } {
            param($UtcNow, $Context, $Descriptor)

            $coordinator = [GraphThrottleCoordinator]::new()
            $scope = New-GraphThrottleScope -Context $Context -Descriptor $Descriptor

            Update-GraphThrottleState -Scope $scope -Qualified $false -RetryAfterSeconds 15 `
                -StatusCode 500 -Coordinator $coordinator -UtcNow $UtcNow

            $coordinator.IsEmpty | Should -BeTrue
        }
    }
}

Describe 'Wait-GraphThrottleGate' {

    It 'waits for the strictest of the coarse and leaf cooldowns, then acquires leaf admission' {
        InModuleScope GraphKit -Parameters @{
            UtcNow     = $script:utcNow
            Context    = $script:context
            Descriptor = $script:descriptor
        } {
            param($UtcNow, $Context, $Descriptor)

            $coordinator = [GraphThrottleCoordinator]::new()
            $scope = New-GraphThrottleScope -Context $Context -Descriptor $Descriptor
            $coordinator.ApplyCooldown($scope.CoarseKey, 60, $UtcNow)
            $coordinator.ApplyCooldown($scope.LeafKey, 30, $UtcNow)

            $delays = [System.Collections.Generic.List[long]]::new()
            $delay = { param($Milliseconds) $delays.Add([long] $Milliseconds) }

            $admission = Wait-GraphThrottleGate -Scope $scope -Coordinator $coordinator `
                -UtcNow $UtcNow -Delay $delay

            $delays.Count | Should -Be 1
            $delays[0] | Should -Be 60000
            $admission.Key | Should -Be $scope.LeafKey
            $admission.Coordinator | Should -Be $coordinator
            $coordinator.GetInFlight($scope.LeafKey) | Should -Be 1
        }
    }

    It 'skips the wait and only acquires admission when no cooldown is active' {
        InModuleScope GraphKit -Parameters @{
            UtcNow     = $script:utcNow
            Context    = $script:context
            Descriptor = $script:descriptor
        } {
            param($UtcNow, $Context, $Descriptor)

            $coordinator = [GraphThrottleCoordinator]::new()
            $scope = New-GraphThrottleScope -Context $Context -Descriptor $Descriptor

            $delays = [System.Collections.Generic.List[long]]::new()
            $delay = { param($Milliseconds) $delays.Add([long] $Milliseconds) }

            $admission = Wait-GraphThrottleGate -Scope $scope -Coordinator $coordinator `
                -UtcNow $UtcNow -Delay $delay

            $delays.Count | Should -Be 0
            $admission.Key | Should -Be $scope.LeafKey
            $coordinator.GetInFlight($scope.LeafKey) | Should -Be 1
        }
    }
}

Describe 'Complete-GraphThrottleGate' {

    It 'releases the admission slot and advances the success streak' {
        InModuleScope GraphKit -Parameters @{
            UtcNow     = $script:utcNow
            Context    = $script:context
            Descriptor = $script:descriptor
        } {
            param($UtcNow, $Context, $Descriptor)

            $coordinator = [GraphThrottleCoordinator]::new()
            $scope = New-GraphThrottleScope -Context $Context -Descriptor $Descriptor
            $coordinator.RecordThrottle($scope.LeafKey, $true, 10, $UtcNow)

            $admission = Wait-GraphThrottleGate -Scope $scope -Coordinator $coordinator -UtcNow $UtcNow
            $coordinator.GetInFlight($scope.LeafKey) | Should -Be 1

            Complete-GraphThrottleGate -Admission $admission -Success

            $coordinator.GetInFlight($scope.LeafKey) | Should -Be 0
            $coordinator.GetSuccessStreak($scope.LeafKey) | Should -Be 1
        }
    }

    It 'rejects an admission record without a coordinator' {
        InModuleScope GraphKit {
            { Complete-GraphThrottleGate -Admission @{ Key = 'leaf' } } | Should -Throw -ExpectedMessage '*no Coordinator*'
        }
    }
}
