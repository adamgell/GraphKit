BeforeAll {
    $repoRoot = (Join-Path $PSScriptRoot '../../..') | Convert-Path

    # Import the built module: it registers the compiled GraphThrottleCoordinator type in
    # this session exactly once. The tests exercise that type directly — no Add-Type and
    # no PowerShell class definitions in test scope.
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) {
        throw 'No built GraphKit module found under output/module/GraphKit. Run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force

    $script:utcNow = [datetime] '2026-01-01T00:00:00Z'
}

Describe 'GraphThrottleCoordinator — AIMD admission control' {

    It 'cuts MaxConcurrent to the floor and applies the cooldown on a qualified throttle' {
        $coordinator = [GraphThrottleCoordinator]::new()

        $coordinator.RecordThrottle('leaf', $true, 30, $script:utcNow)

        $coordinator.GetMaxConcurrent('leaf') | Should -Be 1
        $coordinator.GetCooldownUntilUtc('leaf') | Should -Be $script:utcNow.AddSeconds(30)
    }

    It 'applies only a cooldown (no admission cut) on an unqualified throttle' {
        $coordinator = [GraphThrottleCoordinator]::new()

        $coordinator.RecordThrottle('coarse', $false, 30, $script:utcNow)

        $coordinator.GetMaxConcurrent('coarse') | Should -Be 8
        $coordinator.GetCooldownUntilUtc('coarse') | Should -Be $script:utcNow.AddSeconds(30)
    }

    It 'restores concurrency additively on a success streak and never exceeds the cap' {
        $coordinator = [GraphThrottleCoordinator]::new()

        $coordinator.RecordThrottle('leaf', $true, 10, $script:utcNow)
        $coordinator.GetMaxConcurrent('leaf') | Should -Be 1

        1..5 | ForEach-Object { $coordinator.RecordSuccess('leaf') }
        $coordinator.GetMaxConcurrent('leaf') | Should -Be 2

        1..5 | ForEach-Object { $coordinator.RecordSuccess('leaf') }
        $coordinator.GetMaxConcurrent('leaf') | Should -Be 3

        1..40 | ForEach-Object { $coordinator.RecordSuccess('leaf') }
        $coordinator.GetMaxConcurrent('leaf') | Should -Be 8
    }

    It 'reports the remaining cooldown as whole milliseconds (rounding up)' {
        $coordinator = [GraphThrottleCoordinator]::new()

        $coordinator.ApplyCooldown('leaf', 30, $script:utcNow)

        $coordinator.GetWaitMilliseconds('leaf', $script:utcNow) | Should -Be 30000
        $coordinator.GetWaitMilliseconds('leaf', $script:utcNow.AddSeconds(30)) | Should -Be 0
        $coordinator.GetWaitMilliseconds('missing', $script:utcNow) | Should -Be 0
    }

    It 'denies admission once MaxConcurrent slots are in use' {
        $coordinator = [GraphThrottleCoordinator]::new()

        $coordinator.RecordThrottle('leaf', $true, 10, $script:utcNow)

        $coordinator.AcquireAdmission('leaf')
        $coordinator.GetInFlight('leaf') | Should -Be 1

        { $coordinator.AcquireAdmission('leaf') } | Should -Throw -ExpectedMessage '*Throttle admission denied*'
    }

    It 'releases an admission slot and only advances the streak on success' {
        $coordinator = [GraphThrottleCoordinator]::new()

        $coordinator.AcquireAdmission('leaf')
        $coordinator.GetInFlight('leaf') | Should -Be 1

        $coordinator.ReleaseAdmission('leaf', $false)
        $coordinator.GetInFlight('leaf') | Should -Be 0
        $coordinator.GetSuccessStreak('leaf') | Should -Be 0

        $coordinator.ReleaseAdmission('leaf', $true)
        $coordinator.GetSuccessStreak('leaf') | Should -Be 1
    }

    It 'keeps per-scope state isolated across keys' {
        $coordinator = [GraphThrottleCoordinator]::new()

        $coordinator.RecordThrottle('tenantA', $true, 30, $script:utcNow)

        $coordinator.GetMaxConcurrent('tenantA') | Should -Be 1
        $coordinator.ContainsKey('tenantB') | Should -BeFalse

        $coordinator.AcquireAdmission('tenantB')
        $coordinator.GetInFlight('tenantB') | Should -Be 1
        $coordinator.GetMaxConcurrent('tenantB') | Should -Be 8
    }
}
