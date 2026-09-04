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
            $coordinator.GetMaxConcurrent($scope.CoarseKey) | Should -Be 2
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
            $coordinator.GetMaxConcurrent($scope.LeafKey) | Should -Be 2
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

    It 'supports an advanced one-parameter delay seam without requiring cancellation support' {
        InModuleScope GraphKit -Parameters @{
            UtcNow     = $script:utcNow
            Context    = $script:context
            Descriptor = $script:descriptor
        } {
            param($UtcNow, $Context, $Descriptor)

            $coordinator = [GraphThrottleCoordinator]::new()
            $scope = New-GraphThrottleScope -Context $Context -Descriptor $Descriptor
            $coordinator.ApplyCooldown($scope.CoarseKey, 1, $UtcNow)
            $delays = [System.Collections.Generic.List[long]]::new()
            $delay = {
                [CmdletBinding()]
                param([long] $Milliseconds)

                $delays.Add($Milliseconds)
            }.GetNewClosure()

            $admission = Wait-GraphThrottleGate -Scope $scope -Coordinator $coordinator `
                -UtcNow $UtcNow -Delay $delay

            try {
                $delays | Should -Be @(1000)
            }
            finally {
                Complete-GraphThrottleGate -Admission $admission
            }
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

    It 'does not delay or acquire when cancellation is already requested before cooldown' {
        $capture = InModuleScope GraphKit -Parameters @{
            UtcNow     = $script:utcNow
            Context    = $script:context
            Descriptor = $script:descriptor
        } {
            param($UtcNow, $Context, $Descriptor)

            $coordinator = [GraphThrottleCoordinator]::new()
            $scope = New-GraphThrottleScope -Context $Context -Descriptor $Descriptor
            $coordinator.ApplyCooldown($scope.CoarseKey, 60, $UtcNow)
            $cts = [System.Threading.CancellationTokenSource]::new()
            $cts.Cancel()
            $delayCalls = [System.Collections.Generic.List[int]]::new()
            $delay = {
                param($Milliseconds)
                $delayCalls.Add([int] $Milliseconds)
            }.GetNewClosure()

            try {
                $failure = $null
                try {
                    $null = Wait-GraphThrottleGate -Scope $scope -Coordinator $coordinator `
                        -UtcNow $UtcNow -CancellationToken $cts.Token `
                        -Delay $delay
                }
                catch {
                    $failure = $_.Exception
                }

                $isCancellation = $false
                $candidate = $failure
                while ($null -ne $candidate) {
                    if ($candidate -is [System.OperationCanceledException]) {
                        $isCancellation = $true
                        break
                    }
                    $candidate = $candidate.InnerException
                }

                [pscustomobject] @{
                    IsCancellation = $isCancellation
                    DelayCalls     = $delayCalls.Count
                    InFlight       = $coordinator.GetInFlight($scope.LeafKey)
                }
            }
            finally {
                $cts.Dispose()
            }
        }

        $capture.IsCancellation | Should -BeTrue
        $capture.DelayCalls | Should -Be 0
        $capture.InFlight | Should -Be 0
    }

    It 'does not acquire a new slot when cancellation is raised by an admission poll' {
        $capture = InModuleScope GraphKit -Parameters @{
            Context    = $script:context
            Descriptor = $script:descriptor
        } {
            param($Context, $Descriptor)

            $coordinator = [GraphThrottleCoordinator]::new()
            $scope = New-GraphThrottleScope -Context $Context -Descriptor $Descriptor
            $coordinator.SetMaxConcurrent($scope.LeafKey, 1)
            $first = Wait-GraphThrottleGate -Scope $scope -Coordinator $coordinator `
                -Delay { param($Milliseconds) }
            $cts = [System.Threading.CancellationTokenSource]::new()
            $delayCalls = [System.Collections.Generic.List[long]]::new()
            $delay = {
                param($Milliseconds, $CancellationToken)
                $delayCalls.Add([long] $Milliseconds)
                $cts.Cancel()
            }.GetNewClosure()

            try {
                $failure = $null
                try {
                    $null = Wait-GraphThrottleGate -Scope $scope -Coordinator $coordinator `
                        -CancellationToken $cts.Token -Delay $delay
                }
                catch {
                    $failure = $_.Exception
                }

                $isCancellation = $false
                $candidate = $failure
                while ($null -ne $candidate) {
                    if ($candidate -is [System.OperationCanceledException]) {
                        $isCancellation = $true
                        break
                    }
                    $candidate = $candidate.InnerException
                }

                [pscustomobject] @{
                    IsCancellation       = $isCancellation
                    DelayCalls           = @($delayCalls)
                    InFlightBeforeCleanup = $coordinator.GetInFlight($scope.LeafKey)
                }
            }
            finally {
                Complete-GraphThrottleGate -Admission $first
                $cts.Dispose()
            }
        }

        $capture.IsCancellation | Should -BeTrue
        $capture.DelayCalls | Should -Be @(50)
        $capture.InFlightBeforeCleanup | Should -Be 1 -Because 'only the original holder may remain admitted'
    }

    It 'clamps a cooldown to the inherited deadline and acquires no admission after expiry' {
        $capture = InModuleScope GraphKit -Parameters @{
            UtcNow     = $script:utcNow
            Context    = $script:context
            Descriptor = $script:descriptor
        } {
            param($UtcNow, $Context, $Descriptor)

            $clock = [pscustomobject] @{ Value = $UtcNow }
            $utcNowScript = { $clock.Value }.GetNewClosure()
            $coordinator = [GraphThrottleCoordinator]::new()
            $scope = New-GraphThrottleScope -Context $Context -Descriptor $Descriptor
            $coordinator.ApplyCooldown($scope.CoarseKey, 60, $UtcNow)
            $delays = [System.Collections.Generic.List[long]]::new()
            $delay = {
                param([long] $Milliseconds, [System.Threading.CancellationToken] $CancellationToken)
                $delays.Add($Milliseconds)
                $clock.Value = $clock.Value.AddMilliseconds($Milliseconds)
            }.GetNewClosure()

            $failure = $null
            try {
                $null = Wait-GraphThrottleGate -Scope $scope -Coordinator $coordinator `
                    -UtcNow $UtcNow -UtcNowScript $utcNowScript `
                    -DeadlineUtc $UtcNow.AddSeconds(5) `
                    -RemainingDeadline ([TimeSpan]::FromSeconds(5)) -Delay $delay
            }
            catch {
                $failure = $_.Exception
            }

            [pscustomobject] @{
                Failure  = $failure
                Delays   = @($delays)
                InFlight = $coordinator.GetInFlight($scope.LeafKey)
            }
        }

        $capture.Failure | Should -BeOfType [System.TimeoutException]
        $capture.Failure.Data['GraphKit.OperationDeadlineExpired'] | Should -BeTrue
        $capture.Delays | Should -HaveCount 1
        $capture.Delays[0] | Should -BeGreaterThan 0
        $capture.Delays[0] | Should -BeLessOrEqual 5000
        $capture.InFlight | Should -Be 0
    }

    It 'clamps admission polling to the inherited deadline without leaking a slot' {
        $capture = InModuleScope GraphKit -Parameters @{
            UtcNow     = $script:utcNow
            Context    = $script:context
            Descriptor = $script:descriptor
        } {
            param($UtcNow, $Context, $Descriptor)

            $clock = [pscustomobject] @{ Value = $UtcNow }
            $utcNowScript = { $clock.Value }.GetNewClosure()
            $coordinator = [GraphThrottleCoordinator]::new()
            $scope = New-GraphThrottleScope -Context $Context -Descriptor $Descriptor
            $coordinator.SetMaxConcurrent($scope.LeafKey, 1)
            $holder = Wait-GraphThrottleGate -Scope $scope -Coordinator $coordinator -Delay { param($Milliseconds) }
            $delays = [System.Collections.Generic.List[long]]::new()
            $delay = {
                param([long] $Milliseconds, [System.Threading.CancellationToken] $CancellationToken)
                $delays.Add($Milliseconds)
                $clock.Value = $clock.Value.AddMilliseconds($Milliseconds)
            }.GetNewClosure()

            try {
                $failure = $null
                try {
                    $null = Wait-GraphThrottleGate -Scope $scope -Coordinator $coordinator `
                        -UtcNow $UtcNow -UtcNowScript $utcNowScript `
                        -DeadlineUtc $UtcNow.AddMilliseconds(75) `
                        -RemainingDeadline ([TimeSpan]::FromMilliseconds(75)) -Delay $delay
                }
                catch {
                    $failure = $_.Exception
                }

                [pscustomobject] @{
                    Failure  = $failure
                    Delays   = @($delays)
                    InFlight = $coordinator.GetInFlight($scope.LeafKey)
                }
            }
            finally {
                Complete-GraphThrottleGate -Admission $holder
            }
        }

        $capture.Failure | Should -BeOfType [System.TimeoutException]
        $capture.Failure.Data['GraphKit.OperationDeadlineExpired'] | Should -BeTrue
        $capture.Delays | Should -Be @(50, 25)
        $capture.InFlight | Should -Be 1 -Because 'only the pre-existing holder may remain admitted'
    }

    It 'gives caller cancellation precedence at the exact cooldown deadline boundary' {
        $capture = InModuleScope GraphKit -Parameters @{
            UtcNow     = $script:utcNow
            Context    = $script:context
            Descriptor = $script:descriptor
        } {
            param($UtcNow, $Context, $Descriptor)

            $clock = [pscustomobject] @{ Value = $UtcNow }
            $utcNowScript = { $clock.Value }.GetNewClosure()
            $coordinator = [GraphThrottleCoordinator]::new()
            $scope = New-GraphThrottleScope -Context $Context -Descriptor $Descriptor
            $coordinator.ApplyCooldown($scope.CoarseKey, 60, $UtcNow)
            $cts = [System.Threading.CancellationTokenSource]::new()
            $delay = {
                param([long] $Milliseconds, [System.Threading.CancellationToken] $CancellationToken)
                $clock.Value = $clock.Value.AddMilliseconds($Milliseconds)
                $cts.Cancel()
            }.GetNewClosure()

            try {
                $failure = $null
                try {
                    $null = Wait-GraphThrottleGate -Scope $scope -Coordinator $coordinator `
                        -UtcNow $UtcNow -UtcNowScript $utcNowScript `
                        -DeadlineUtc $UtcNow.AddSeconds(5) `
                        -RemainingDeadline ([TimeSpan]::FromSeconds(5)) `
                        -CancellationToken $cts.Token -Delay $delay
                }
                catch {
                    $failure = $_.Exception
                }

                [pscustomobject] @{
                    Failure  = $failure
                    InFlight = $coordinator.GetInFlight($scope.LeafKey)
                }
            }
            finally {
                $cts.Dispose()
            }
        }

        $isCancellation = $false
        $candidate = $capture.Failure
        while ($null -ne $candidate) {
            if ($candidate -is [System.OperationCanceledException]) {
                $isCancellation = $true
                break
            }
            $candidate = $candidate.InnerException
        }
        $isCancellation | Should -BeTrue
        $capture.InFlight | Should -Be 0
    }

    It 'preserves the admission back-pressure timeout when it expires before the operation deadline' {
        $capture = InModuleScope GraphKit -Parameters @{
            UtcNow     = $script:utcNow
            Context    = $script:context
            Descriptor = $script:descriptor
        } {
            param($UtcNow, $Context, $Descriptor)

            $clock = [pscustomobject] @{ Value = $UtcNow }
            $utcNowScript = { $clock.Value }.GetNewClosure()
            $coordinator = [GraphThrottleCoordinator]::new()
            $scope = New-GraphThrottleScope -Context $Context -Descriptor $Descriptor
            $coordinator.SetMaxConcurrent($scope.LeafKey, 1)
            $holder = Wait-GraphThrottleGate -Scope $scope -Coordinator $coordinator -Delay { param($Milliseconds) }
            $delay = {
                param([long] $Milliseconds, [System.Threading.CancellationToken] $CancellationToken)
                $clock.Value = $clock.Value.AddMilliseconds($Milliseconds)
            }.GetNewClosure()

            try {
                $failure = $null
                try {
                    $null = Wait-GraphThrottleGate -Scope $scope -Coordinator $coordinator `
                        -UtcNow $UtcNow -UtcNowScript $utcNowScript `
                        -DeadlineUtc $UtcNow.AddSeconds(5) `
                        -RemainingDeadline ([TimeSpan]::FromSeconds(5)) `
                        -AdmissionTimeoutSeconds 1 -Delay $delay
                }
                catch {
                    $failure = $_.Exception
                }

                [pscustomobject] @{
                    Failure  = $failure
                    InFlight = $coordinator.GetInFlight($scope.LeafKey)
                }
            }
            finally {
                Complete-GraphThrottleGate -Admission $holder
            }
        }

        $capture.Failure | Should -Not -BeNullOrEmpty
        $capture.Failure.Message | Should -BeLike '*Throttle admission timed out after 1s*back-pressure*'
        $capture.Failure.Data['GraphKit.OperationDeadlineExpired'] | Should -Not -BeTrue
        $capture.InFlight | Should -Be 1 -Because 'only the pre-existing holder may remain admitted'
    }

    It 'gives caller cancellation precedence when the final admission attempt reaches the back-pressure timeout' {
        $capture = InModuleScope GraphKit {
            $cts = [System.Threading.CancellationTokenSource]::new()
            $coordinator = [pscustomobject] @{
                Attempts = 0
                Releases = 0
                Cts      = $cts
            }
            $coordinator | Add-Member -MemberType ScriptMethod -Name GetWaitMilliseconds -Value {
                param($Key, $UtcNow)
                return 0L
            }
            $coordinator | Add-Member -MemberType ScriptMethod -Name TryAcquireAdmission -Value {
                param($Key)
                $this.Attempts++
                if ($this.Attempts -eq 21) {
                    $this.Cts.Cancel()
                }
                return $false
            }
            $coordinator | Add-Member -MemberType ScriptMethod -Name ReleaseAdmission -Value {
                param($Key, $Success)
                $this.Releases++
            }

            try {
                $failure = $null
                try {
                    $null = Wait-GraphThrottleGate -Scope @{ CoarseKey = 'coarse'; LeafKey = 'leaf' } `
                        -Coordinator $coordinator -CancellationToken $cts.Token `
                        -AdmissionTimeoutSeconds 1 -Delay { param($Milliseconds, $CancellationToken) }
                }
                catch {
                    $failure = $_.Exception
                }

                $isCancellation = $false
                $candidate = $failure
                while ($null -ne $candidate) {
                    if ($candidate -is [System.OperationCanceledException]) {
                        $isCancellation = $true
                        break
                    }
                    $candidate = $candidate.InnerException
                }

                [pscustomobject] @{
                    Failure        = $failure
                    IsCancellation = $isCancellation
                    Attempts       = $coordinator.Attempts
                    Releases       = $coordinator.Releases
                }
            }
            finally {
                $cts.Dispose()
            }
        }

        $capture.IsCancellation | Should -BeTrue
        $capture.Failure.Message | Should -Not -BeLike '*back-pressure*'
        $capture.Attempts | Should -Be 21
        $capture.Releases | Should -Be 0 -Because 'no slot was acquired in the cancellation race'
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
