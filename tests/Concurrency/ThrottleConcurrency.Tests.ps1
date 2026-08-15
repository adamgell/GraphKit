BeforeAll {
    $repoRoot = (Join-Path $PSScriptRoot '../..') | Convert-Path

    # Import the built module: it owns every private function and registers the
    # GraphThrottleCoordinator C# type exactly once, so tests never dot-source
    # source/ files or define types in test scope.
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) {
        throw 'No built GraphKit module found under output/module/GraphKit. Run ./build.ps1 -Tasks build first.'
    }
    $script:modulePath = Join-Path $built.FullName 'GraphKit.psd1'
    Import-Module $script:modulePath -Force

    # Child runspaces need Pester's InModuleScope to reach the private throttle
    # functions; hand them the exact Pester module the test run is using.
    $script:pesterModulePath = (Get-Module Pester).Path

    $script:contextA = [pscustomobject]@{
        Cloud    = 'Global'
        TenantId = [guid] '01234567-89ab-cdef-0123-456789abcdef'
        ClientId = [guid] '11111111-1111-1111-1111-111111111111'
    }
    $script:contextB = [pscustomobject]@{
        Cloud    = 'Global'
        TenantId = [guid] '22222222-2222-2222-2222-222222222222'
        ClientId = [guid] '11111111-1111-1111-1111-111111111111'
    }
    $script:descriptor = @{
        ThrottleClass  = 'Read'
        ResourceFamily = 'Intune.ManagedDevices'
    }

    # Launches one runspace per argument set, all in parallel (BeginInvoke), then waits.
    # Child runspaces import the built module (their own module state) and reach the
    # private Wait-GraphThrottleGate through InModuleScope. They must NOT re-define the
    # coordinator class — the module guards its Add-Type, so the single coordinator
    # instance passed from the test stays the one thread-safe state shared by every
    # runspace.
    function Invoke-ThrottleRunspaces {
        param(
            [scriptblock] $Child,
            [System.Collections.Generic.List[object]] $ArgumentSets
        )

        $jobs = [System.Collections.Generic.List[object]]::new()
        $handles = [System.Collections.Generic.List[object]]::new()

        foreach ($argumentSet in $ArgumentSets) {
            $ps = [powershell]::Create()
            [void] $ps.AddScript($Child)
            foreach ($arg in $argumentSet) {
                [void] $ps.AddArgument($arg)
            }
            $handles.Add($ps.BeginInvoke())
            $jobs.Add($ps)
        }

        for ($i = 0; $i -lt $jobs.Count; $i++) {
            [void] $jobs[$i].EndInvoke($handles[$i])
            $jobs[$i].Dispose()
        }
    }
}

Describe 'Scoped throttle under real runspaces' {
    It 'admits only MaxConcurrent runspaces concurrently' {
        $coordinator = [GraphThrottleCoordinator]::new()
        $scope = InModuleScope GraphKit -Parameters @{
            Context    = $script:contextA
            Descriptor = $script:descriptor
        } {
            param($Context, $Descriptor)
            New-GraphThrottleScope -Context $Context -Descriptor $Descriptor
        }
        $coordinator.SetMaxConcurrent($scope.LeafKey, 3)

        $runspaceCount = 8
        $barrier = [System.Threading.Barrier]::new($runspaceCount)
        $results = [System.Collections.Concurrent.ConcurrentBag[object]]::new()

        $child = {
            param($modulePath, $pesterPath, $coordinator, $scope, $barrier, $results)
            Import-Module $modulePath -Force -ErrorAction Stop
            Import-Module $pesterPath -ErrorAction Stop
            InModuleScope GraphKit -Parameters @{
                Coordinator = $coordinator
                Scope       = $scope
                Barrier     = $barrier
                Results     = $results
            } {
                param($Coordinator, $Scope, $Barrier, $Results)
                try {
                    [void] $Barrier.SignalAndWait(10000)
                    # Admission now WAITS for a free slot rather than throwing on
                    # contention (see the 2026-08-15 review: throwing turned
                    # back-pressure into an InvalidOperationException in the request
                    # path). No runspace here ever releases, so the excess must time
                    # out - bounded tightly so the property is proven in seconds.
                    $null = Wait-GraphThrottleGate -Scope $Scope -Coordinator $Coordinator `
                        -UtcNow ([datetime]::UtcNow) -AdmissionTimeoutSeconds 2
                    $Results.Add(@{ Outcome = 'Acquired' })
                }
                catch {
                    $Results.Add(@{ Outcome = 'Denied'; Error = $_.Exception.Message })
                }
            }
        }

        $argumentSets = [System.Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt $runspaceCount; $i++) {
            $argumentSets.Add([object[]] @($script:modulePath, $script:pesterModulePath, $coordinator, $scope, $barrier, $results))
        }

        Invoke-ThrottleRunspaces -Child $child -ArgumentSets $argumentSets

        ($results | Where-Object { $_.Outcome -eq 'Acquired' }).Count | Should -Be 3
        ($results | Where-Object { $_.Outcome -eq 'Denied' }).Count | Should -Be 5
        ($results | Where-Object { $_.Outcome -eq 'Denied' }) |
            ForEach-Object { $_.Error | Should -Match 'admission timed out' }
        $coordinator.GetInFlight($scope.LeafKey) | Should -Be 3
    }

    It 'every runspace observes the scoped cooldown' {
        $coordinator = [GraphThrottleCoordinator]::new()
        $scope = InModuleScope GraphKit -Parameters @{
            Context    = $script:contextA
            Descriptor = $script:descriptor
        } {
            param($Context, $Descriptor)
            New-GraphThrottleScope -Context $Context -Descriptor $Descriptor
        }
        $coordinator.ApplyCooldown($scope.LeafKey, 30, [datetime]::UtcNow)

        # This test isolates COOLDOWN observation, so give it enough admission slots for
        # every runspace. Scopes now start at a conservative initial concurrency and ramp,
        # so without this the excess runspaces would serialize behind admission and the
        # test would be measuring admission rather than the cooldown it names.
        $runspaceCount = 5
        $coordinator.SetMaxConcurrent($scope.LeafKey, $runspaceCount)
        $barrier = [System.Threading.Barrier]::new($runspaceCount)
        $delays = [System.Collections.Concurrent.ConcurrentBag[long]]::new()

        $child = {
            param($modulePath, $pesterPath, $coordinator, $scope, $barrier, $delays)
            Import-Module $modulePath -Force -ErrorAction Stop
            Import-Module $pesterPath -ErrorAction Stop
            InModuleScope GraphKit -Parameters @{
                Coordinator = $coordinator
                Scope       = $scope
                Barrier     = $barrier
                Delays      = $delays
            } {
                param($Coordinator, $Scope, $Barrier, $Delays)
                $delay = { param($Milliseconds) $Delays.Add([long] $Milliseconds) }
                [void] $Barrier.SignalAndWait(10000)
                $null = Wait-GraphThrottleGate -Scope $Scope -Coordinator $Coordinator `
                    -UtcNow ([datetime]::UtcNow) -Delay $delay
            }
        }

        $argumentSets = [System.Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt $runspaceCount; $i++) {
            $argumentSets.Add([object[]] @($script:modulePath, $script:pesterModulePath, $coordinator, $scope, $barrier, $delays))
        }

        Invoke-ThrottleRunspaces -Child $child -ArgumentSets $argumentSets

        $delays.Count | Should -Be $runspaceCount
        $delays | ForEach-Object { $_ | Should -BeGreaterThan 0 }
    }

    It 'keeps tenant B unblocked while tenant A is throttled' {
        $coordinator = [GraphThrottleCoordinator]::new()
        $scopeA = InModuleScope GraphKit -Parameters @{
            Context    = $script:contextA
            Descriptor = $script:descriptor
        } {
            param($Context, $Descriptor)
            New-GraphThrottleScope -Context $Context -Descriptor $Descriptor
        }
        $scopeB = InModuleScope GraphKit -Parameters @{
            Context    = $script:contextB
            Descriptor = $script:descriptor
        } {
            param($Context, $Descriptor)
            New-GraphThrottleScope -Context $Context -Descriptor $Descriptor
        }
        $coordinator.ApplyCooldown($scopeA.LeafKey, 30, [datetime]::UtcNow)

        $barrier = [System.Threading.Barrier]::new(4)
        $results = [System.Collections.Concurrent.ConcurrentBag[object]]::new()

        $child = {
            param($modulePath, $pesterPath, $coordinator, $scope, $tag, $barrier, $results)
            Import-Module $modulePath -Force -ErrorAction Stop
            Import-Module $pesterPath -ErrorAction Stop
            InModuleScope GraphKit -Parameters @{
                Coordinator = $coordinator
                Scope       = $scope
                Tag         = $tag
                Barrier     = $barrier
                Results     = $results
            } {
                param($Coordinator, $Scope, $Tag, $Barrier, $Results)
                $delay = { param($Milliseconds) $Results.Add(@{ Tag = $Tag; Kind = 'Delay'; Ms = [long] $Milliseconds }) }
                try {
                    [void] $Barrier.SignalAndWait(10000)
                    $null = Wait-GraphThrottleGate -Scope $Scope -Coordinator $Coordinator `
                        -UtcNow ([datetime]::UtcNow) -Delay $delay
                    $Results.Add(@{ Tag = $Tag; Kind = 'Acquired' })
                }
                catch {
                    $Results.Add(@{ Tag = $Tag; Kind = 'Denied'; Error = $_.Exception.Message })
                }
            }
        }

        $argumentSets = [System.Collections.Generic.List[object]]::new()
        $argumentSets.Add([object[]] @($script:modulePath, $script:pesterModulePath, $coordinator, $scopeA, 'A', $barrier, $results))
        $argumentSets.Add([object[]] @($script:modulePath, $script:pesterModulePath, $coordinator, $scopeA, 'A', $barrier, $results))
        $argumentSets.Add([object[]] @($script:modulePath, $script:pesterModulePath, $coordinator, $scopeB, 'B', $barrier, $results))
        $argumentSets.Add([object[]] @($script:modulePath, $script:pesterModulePath, $coordinator, $scopeB, 'B', $barrier, $results))

        Invoke-ThrottleRunspaces -Child $child -ArgumentSets $argumentSets

        $tenantADelays = $results | Where-Object { $_.Tag -eq 'A' -and $_.Kind -eq 'Delay' }
        $tenantBDelays = $results | Where-Object { $_.Tag -eq 'B' -and $_.Kind -eq 'Delay' }

        $tenantADelays.Count | Should -Be 2
        $tenantADelays | ForEach-Object { $_.Ms | Should -BeGreaterThan 0 }
        $tenantBDelays.Count | Should -Be 0
        ($results | Where-Object { $_.Tag -eq 'B' -and $_.Kind -eq 'Acquired' }).Count | Should -Be 2
        ($results | Where-Object { $_.Tag -eq 'A' -and $_.Kind -eq 'Acquired' }).Count | Should -Be 2
    }
}
