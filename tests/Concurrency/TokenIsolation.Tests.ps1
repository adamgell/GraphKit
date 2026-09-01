<#
    Cross-context token isolation.

    The auth gate proves ONE Ivy24 acquisition. That does not prove isolation, which is
    the entire reason the Graph SDK was rejected as a transport: its state is
    process-global and leaks across runspaces, so a tenant switch in one runspace
    retargets every other. A per-context token source is only an improvement if it
    actually keeps contexts apart.

    Note on structure: this file retains direct per-instance coverage for the legacy
    PowerShell-class sources. Task 7's GraphKitAuthRunspace.Tests.ps1 separately proves that
    one exact compiled parent source crosses real thread runspaces by reference. These legacy
    fixtures stay module-scoped because their compatibility boundary intentionally rejects
    cross-runspace acquisition.
#>

BeforeAll {
    $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    # Discover the built version rather than naming it: a hard-coded path silently
    # breaks the whole file on any version bump, which is exactly what happened.
    $built = Get-ChildItem -Path (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) {
        throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first, then re-run the tests.'
    }
    $script:ModulePath = Join-Path $built.FullName 'GraphKit.psd1'
    Import-Module $script:ModulePath -Force -ErrorAction Stop

    # A child runspace needs Pester too: InModuleScope is a Pester command, and without it
    # the source construction silently yields $null and the token comes back empty.
    $script:PesterModulePath = (Get-Module Pester | Select-Object -First 1).Path

    # Builds a confidential-client source over a stub MSAL application that counts
    # acquisitions and returns a token naming its tenant, so a token reaching the wrong
    # context is immediately identifiable rather than merely "a token".
    $script:SourceFactoryScript = {
        param([string] $Tenant, $Counter, $ForceRefreshFlags)

        # State is carried on the objects themselves ($this) rather than in closures:
        # ScriptMethod bodies do not reliably see variables captured by GetNewClosure at
        # the point they are later invoked, which silently yields a null Counter.
        $factory = {
            $app = [pscustomobject] @{
                Tenant            = $Tenant
                Counter           = $Counter
                ForceRefreshFlags = $ForceRefreshFlags
            }
            $app | Add-Member -MemberType ScriptMethod -Name AcquireTokenForClient -Value {
                param($Scopes)
                $builder = [pscustomobject] @{
                    Tenant            = $this.Tenant
                    Counter           = $this.Counter
                    ForceRefreshFlags = $this.ForceRefreshFlags
                }
                $builder | Add-Member -MemberType ScriptMethod -Name WithForceRefresh -Value {
                    param([bool] $ForceRefresh)
                    $this.ForceRefreshFlags.Enqueue($ForceRefresh)
                    return $this
                }
                $builder | Add-Member -MemberType ScriptMethod -Name ExecuteAsync -Value {
                    param($Cancellation)
                    $null = $this.Counter.AddOrUpdate($this.Tenant, 1, [Func[string, int, int]] { param($k, $v) $v + 1 })
                    $auth = [pscustomobject] @{
                        AccessToken = "TOKEN-FOR-$($this.Tenant)"
                        ExpiresOn   = [System.DateTimeOffset]::UtcNow.AddHours(1)
                    }
                    $task = [pscustomobject] @{ Auth = $auth }
                    $task | Add-Member -MemberType ScriptMethod -Name GetAwaiter -Value {
                        $awaiter = [pscustomobject] @{ Auth = $this.Auth }
                        $awaiter | Add-Member -MemberType ScriptMethod -Name GetResult -Value { return $this.Auth }
                        return $awaiter
                    }
                    return $task
                }
                return $builder
            }
            return $app
        }.GetNewClosure()

        return [ConfidentialClientTokenSource]::new(
            $factory, 'Certificate', 'https://graph.microsoft.com', 'client-id', "gen-$Tenant")
    }

    function New-TestTokenSource {
        param(
            [string] $Tenant,
            $Counter,
            $ForceRefreshFlags = ([System.Collections.Concurrent.ConcurrentQueue[bool]]::new())
        )
        InModuleScope GraphKit -Parameters @{ T = $Tenant; C = $Counter; Q = $ForceRefreshFlags; F = $script:SourceFactoryScript } {
            param($T, $C, $Q, $F)
            & $F $T $C $Q
        }
    }

    function New-TestManagedIdentitySource {
        param($ForceRefreshFlags)

        InModuleScope GraphKit -Parameters @{ Q = $ForceRefreshFlags } {
            param($Q)

            $factory = {
                $app = [pscustomobject] @{ ForceRefreshFlags = $Q }
                $app | Add-Member -MemberType ScriptMethod -Name AcquireTokenForManagedIdentity -Value {
                    param($Scope)
                    $builder = [pscustomobject] @{ ForceRefreshFlags = $this.ForceRefreshFlags }
                    $builder | Add-Member -MemberType ScriptMethod -Name WithForceRefresh -Value {
                        param([bool] $ForceRefresh)
                        $this.ForceRefreshFlags.Enqueue($ForceRefresh)
                        return $this
                    }
                    $builder | Add-Member -MemberType ScriptMethod -Name ExecuteAsync -Value {
                        param($Cancellation)
                        $auth = [pscustomobject] @{
                            AccessToken = 'TOKEN-FOR-MANAGED-IDENTITY'
                            ExpiresOn   = [System.DateTimeOffset]::UtcNow.AddHours(1)
                        }
                        $task = [pscustomobject] @{ Auth = $auth }
                        $task | Add-Member -MemberType ScriptMethod -Name GetAwaiter -Value {
                            $awaiter = [pscustomobject] @{ Auth = $this.Auth }
                            $awaiter | Add-Member -MemberType ScriptMethod -Name GetResult -Value { return $this.Auth }
                            return $awaiter
                        }
                        return $task
                    }
                    return $builder
                }
                return $app
            }.GetNewClosure()

            return [ManagedIdentityTokenSource]::new(
                $factory, 'https://graph.microsoft.com', 'client-id', 'managed-generation')
        }
    }
}

Describe 'Token isolation: a context receives only its own token' {

    # NOTE ON STRUCTURE. An earlier version of this ran two real runspaces. It was
    # removed, not weakened: Pester's InModuleScope does not function inside a bare
    # [powershell]::Create() runspace outside a Pester run, so the child could not
    # construct a module-scoped token source and the test measured nothing.
    #
    # More importantly, a runspace would not add signal here. The isolation claim is
    # that each context owns its OWN token source, so there is no shared state for a
    # second thread to observe - that is precisely the difference from the Graph SDK,
    # whose state is process-global .NET statics. Instance separation is therefore the
    # property, and it is provable directly. Concurrency IS tested where shared state
    # genuinely exists: the throttle coordinator, in ThrottleConcurrency.Tests.ps1.

    It 'gives each tenant a token naming only that tenant' {
        $counter = [System.Collections.Concurrent.ConcurrentDictionary[string, int]]::new()
        $sourceA = New-TestTokenSource -Tenant 'tenant-a' -Counter $counter
        $sourceB = New-TestTokenSource -Tenant 'tenant-b' -Counter $counter

        $tokenA = $sourceA.Acquire($false, [System.Threading.CancellationToken]::None)
        $tokenB = $sourceB.Acquire($false, [System.Threading.CancellationToken]::None)

        $tokenA.AccessToken | Should -Be 'TOKEN-FOR-tenant-a'
        $tokenB.AccessToken | Should -Be 'TOKEN-FOR-tenant-b'
        $tokenA.AccessToken | Should -Not -Be $tokenB.AccessToken -Because 'a context must never receive another context''s token'
    }

    It 'holds no state that a second source can observe' {
        # The structural claim behind the whole design: two sources share nothing, so
        # acquiring on one cannot change what the other returns or caches.
        $counter = [System.Collections.Concurrent.ConcurrentDictionary[string, int]]::new()
        $sourceA = New-TestTokenSource -Tenant 'tenant-a' -Counter $counter
        $sourceB = New-TestTokenSource -Tenant 'tenant-b' -Counter $counter

        1..4 | ForEach-Object { $null = $sourceA.Acquire($false, [System.Threading.CancellationToken]::None) }

        $sourceB.ExpiresOn | Should -Be ([System.DateTimeOffset]::MinValue) -Because 'B must still be unacquired after four acquisitions on A'
        $counter.ContainsKey('tenant-b') | Should -BeFalse
    }
}

Describe 'Token isolation: refresh and caching stay context-local' {

    It 'forwards the force-refresh decision to the confidential-client builder' {
        $counter = [System.Collections.Concurrent.ConcurrentDictionary[string, int]]::new()
        $flags = [System.Collections.Concurrent.ConcurrentQueue[bool]]::new()
        $source = New-TestTokenSource -Tenant 'force-confidential' -Counter $counter -ForceRefreshFlags $flags

        $null = $source.Acquire($false, [System.Threading.CancellationToken]::None)
        $null = $source.Acquire($true, [System.Threading.CancellationToken]::None)

        @($flags.ToArray()) | Should -Be @($false, $true)
    }

    It 'forwards the force-refresh decision to the managed-identity builder' {
        $flags = [System.Collections.Concurrent.ConcurrentQueue[bool]]::new()
        $source = New-TestManagedIdentitySource -ForceRefreshFlags $flags

        $null = $source.Acquire($false, [System.Threading.CancellationToken]::None)
        $null = $source.Acquire($true, [System.Threading.CancellationToken]::None)

        @($flags.ToArray()) | Should -Be @($false, $true)
    }

    It 'a forced refresh on one context leaves another untouched' {
        # The single 401 force-refresh must not be a global event: that is precisely the
        # process-global behaviour the SDK transport was rejected for.
        $counter = [System.Collections.Concurrent.ConcurrentDictionary[string, int]]::new()
        $sourceA = New-TestTokenSource -Tenant 'tenant-a' -Counter $counter
        $sourceB = New-TestTokenSource -Tenant 'tenant-b' -Counter $counter

        $null = $sourceA.Acquire($false, [System.Threading.CancellationToken]::None)
        $null = $sourceB.Acquire($false, [System.Threading.CancellationToken]::None)
        $counter['tenant-a'] | Should -Be 1
        $counter['tenant-b'] | Should -Be 1

        $null = $sourceA.Acquire($true, [System.Threading.CancellationToken]::None)

        $counter['tenant-a'] | Should -Be 2 -Because 'the forced refresh must reacquire for A'
        $counter['tenant-b'] | Should -Be 1 -Because 'a 401 on one context is not a global event'
    }

    It 'serves the cached token while it is well inside its refresh skew' {
        $counter = [System.Collections.Concurrent.ConcurrentDictionary[string, int]]::new()
        $source = New-TestTokenSource -Tenant 'tenant-c' -Counter $counter

        1..5 | ForEach-Object { $null = $source.Acquire($false, [System.Threading.CancellationToken]::None) }

        $counter['tenant-c'] | Should -Be 1 -Because 'a one-hour token is far outside the skew, so one acquisition serves all five calls'
    }

    It 'each context caches independently' {
        $counter = [System.Collections.Concurrent.ConcurrentDictionary[string, int]]::new()
        $sourceA = New-TestTokenSource -Tenant 'tenant-a' -Counter $counter
        $sourceB = New-TestTokenSource -Tenant 'tenant-b' -Counter $counter

        1..3 | ForEach-Object { $null = $sourceA.Acquire($false, [System.Threading.CancellationToken]::None) }
        # ConcurrentDictionary has no entry at all for a tenant that never acquired,
        # which is a stronger statement than a zero count.
        $counter.ContainsKey('tenant-b') | Should -BeFalse -Because 'A''s traffic must never populate or consume B''s cache'

        $tokenB = $sourceB.Acquire($false, [System.Threading.CancellationToken]::None)
        $tokenB.AccessToken | Should -Be 'TOKEN-FOR-tenant-b'
    }
}

Describe 'Token isolation: a fixed bearer cannot be refreshed' {

    It 'reports CanRefresh false and fails loudly on a forced refresh' {
        $source = InModuleScope GraphKit {
            [FixedBearerTokenSource]::new('FIXED-TOKEN', 'https://graph.microsoft.com', 'gen')
        }

        $source.CanRefresh | Should -BeFalse -Because 'the retry engine consults CanRefresh before forcing a refresh'

        $first = $source.Acquire($false, [System.Threading.CancellationToken]::None)
        $first.AccessToken | Should -Be 'FIXED-TOKEN'

        # Reaching a forced refresh on an unrefreshable source is a caller error. It must
        # fail rather than hand back the same token the service has already rejected.
        { $source.Acquire($true, [System.Threading.CancellationToken]::None) } |
            Should -Throw -ExpectedMessage '*cannot be refreshed*'
    }
}
