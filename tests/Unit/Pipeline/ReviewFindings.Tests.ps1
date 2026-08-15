<#
    Regression tests for defects found in the 2026-08-15 code review.

    Every test here corresponds to a bug that the 510-test suite did NOT catch, which
    is why each is written to fail against the pre-fix behaviour rather than merely
    describe the fixed behaviour.
#>

BeforeAll {
    $repoRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    . (Join-Path $repoRoot 'source/Private/Get-GraphRetryDecision.ps1')
    . (Join-Path $repoRoot 'source/Private/GraphThrottleCoordinator.ps1')
    . (Join-Path $repoRoot 'source/Private/Wait-GraphThrottleGate.ps1')
    . (Join-Path $repoRoot 'source/Private/Complete-GraphThrottleGate.ps1')
    . (Join-Path $repoRoot 'source/Private/TokenSources/GraphTokenSource.ps1')
}

Describe 'Review finding: ReplayPolicy is authoritative on the ambiguous path' {
    # Previously $safe = $isRead -or $replayPolicy -eq 'Safe', so the HTTP verb
    # overrode an explicit NeverReplay on a GET. The descriptor was honoured on the
    # Rejected path but ignored on Ambiguous - the path where commit state is unknown.

    It 'does not replay a NeverReplay <Method> when the attempt is <Certainty> (status <Status>)' -ForEach @(
        @{ Method = 'GET';  Certainty = 'Ambiguous'; Status = 503 }
        @{ Method = 'GET';  Certainty = 'Ambiguous'; Status = 0 }
        @{ Method = 'HEAD'; Certainty = 'Ambiguous'; Status = 504 }
        @{ Method = 'GET';  Certainty = 'Rejected';  Status = 429 }
        @{ Method = 'POST'; Certainty = 'Ambiguous'; Status = 503 }
    ) {
        $decision = Get-GraphRetryDecision `
            -Descriptor @{ ReplayPolicy = 'NeverReplay'; Condition = $null } `
            -Method $Method -StatusCode $Status -AttemptCertainty $Certainty -CanRefresh $true

        $decision.ShouldRetry | Should -BeFalse -Because 'NeverReplay is intrinsic and must not be overridden by the HTTP verb'
    }

    It 'still replays a <Policy> <Method> on an ambiguous transport failure' -ForEach @(
        @{ Policy = 'Safe'; Method = 'GET' }
        @{ Policy = 'Safe'; Method = 'POST' }
        @{ Policy = 'Conditional'; Method = 'GET' }
    ) {
        # Regression guard: tightening NeverReplay must not stop ordinary reads retrying.
        $decision = Get-GraphRetryDecision `
            -Descriptor @{ ReplayPolicy = $Policy; Condition = $null } `
            -Method $Method -StatusCode 503 -AttemptCertainty 'Ambiguous' -CanRefresh $true

        $decision.ShouldRetry | Should -BeTrue
    }
}

Describe 'Review finding: admission control waits rather than throwing' {
    # Wait-GraphThrottleGate waited out the cooldown then called AcquireAdmission
    # unconditionally, which throws when every slot is busy. That fired exactly when a
    # qualified 429 had cut MaxConcurrent to the floor - turning back-pressure into an
    # InvalidOperationException in the request path.

    It 'waits for a slot instead of throwing when concurrency is at the floor' {
        $coordinator = New-Object -TypeName GraphThrottleCoordinator
        $scope = @{ CoarseKey = 'coarse'; LeafKey = 'leaf-wait' }
        $coordinator.SetMaxConcurrent('leaf-wait', 1)

        $first = Wait-GraphThrottleGate -Scope $scope -Coordinator $coordinator -Delay { param($Milliseconds) }
        $coordinator.GetInFlight('leaf-wait') | Should -Be 1

        # The injected delay releases the first slot on the first poll, so the second
        # caller must observe a wait and then succeed - never an exception.
        $script:pending = $first
        $script:releasedOnce = $false
        $releasingDelay = {
            param($Milliseconds)
            if (-not $script:releasedOnce) {
                $script:releasedOnce = $true
                Complete-GraphThrottleGate -Admission $script:pending -Success
            }
        }

        $second = { Wait-GraphThrottleGate -Scope $scope -Coordinator $coordinator -Delay $releasingDelay }
        $second | Should -Not -Throw

        $script:releasedOnce | Should -BeTrue -Because 'the second caller must have waited at least one poll'
    }

    It 'reports back-pressure as a timeout, not a transport error, when no slot frees' {
        $coordinator = New-Object -TypeName GraphThrottleCoordinator
        $scope = @{ CoarseKey = 'coarse'; LeafKey = 'leaf-timeout' }
        $coordinator.SetMaxConcurrent('leaf-timeout', 1)
        $null = Wait-GraphThrottleGate -Scope $scope -Coordinator $coordinator -Delay { param($Milliseconds) }

        {
            Wait-GraphThrottleGate -Scope $scope -Coordinator $coordinator `
                -Delay { param($Milliseconds) } -AdmissionTimeoutSeconds 1
        } | Should -Throw -ExpectedMessage '*admission timed out*'
    }

    # NOTE: "begins conservatively" is deliberately NOT asserted. The coordinator starts
    # at the cap, which the spec's AIMD guidance argues against, but that is a tuning
    # decision rather than a demonstrated defect - it is recorded as an open question in
    # GraphThrottleCoordinator.ps1 instead of being changed under a bug-fix commit.
}

Describe 'Review finding: cached tokens carry an adaptive refresh skew' {
    # HasValidCachedToken was ExpiresOnUtc -gt UtcNow, so a token expiring in
    # milliseconds was served as valid. The request then drew a 401 and spent the
    # single permitted force-refresh on an entirely predictable failure.

    BeforeAll {
        function New-TestTokenResult {
            param([int] $LifetimeMinutes, [string] $Fingerprint = ('7f' + ('a' * 62)))
            $r = [GraphTokenResult]::new()
            $r.ReceivedOnUtc = [System.DateTimeOffset]::UtcNow
            $r.ExpiresOnUtc = $r.ReceivedOnUtc.AddMinutes($LifetimeMinutes)
            $r.TokenFingerprint = $Fingerprint
            return $r
        }
        $script:Source = [FixedBearerTokenSource]::new('t', 'https://graph.microsoft.com', 'gen')
    }

    It 'applies at least the 60s floor for a <LifetimeMinutes>-minute token' -ForEach @(
        @{ LifetimeMinutes = 2 }
        @{ LifetimeMinutes = 10 }
    ) {
        $skew = $script:Source.RefreshSkewSeconds((New-TestTokenResult -LifetimeMinutes $LifetimeMinutes))
        $skew | Should -BeGreaterOrEqual 60
    }

    It 'uses 10% of lifetime once that exceeds the floor' {
        # 60 minutes -> 10% = 360s, clamped by the 300s ceiling, plus spread.
        $skew = $script:Source.RefreshSkewSeconds((New-TestTokenResult -LifetimeMinutes 60))
        $skew | Should -BeGreaterOrEqual 300
    }

    It 'never exceeds the 300s ceiling by more than the 10% spread' {
        $skew = $script:Source.RefreshSkewSeconds((New-TestTokenResult -LifetimeMinutes 600))
        $skew | Should -BeLessOrEqual 330
    }

    It 'staggers the spread across different tokens so bulk connects do not reacquire in lockstep' {
        $a = $script:Source.RefreshSkewSeconds((New-TestTokenResult -LifetimeMinutes 60 -Fingerprint ('00' + ('a' * 62))))
        $b = $script:Source.RefreshSkewSeconds((New-TestTokenResult -LifetimeMinutes 60 -Fingerprint ('ff' + ('a' * 62))))
        $a | Should -Not -Be $b
    }

    It 'is deterministic for the same token so tests stay reproducible' {
        $r = New-TestTokenResult -LifetimeMinutes 60
        $script:Source.RefreshSkewSeconds($r) | Should -Be $script:Source.RefreshSkewSeconds($r)
    }
}

Describe 'Review finding: descriptor PathTemplate must be host-relative and rooted' {
    # Resolve-GraphUri concatenates base + path, so a template missing its leading
    # '/' produces 'https://graph.microsoft.comdeviceManagement' - a different host,
    # which trips the authority guard far from the actual cause.

    BeforeAll {
        $script:RepoRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
        $script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "gkdesc-$([guid]::NewGuid().ToString('N'))"
        New-Item -ItemType Directory -Path $script:TempDir -Force | Out-Null

        function New-DescriptorFile {
            param([string] $PathTemplate)
            $file = Join-Path $script:TempDir "d-$([guid]::NewGuid().ToString('N')).psd1"
            Set-Content -LiteralPath $file -Value @"
@{
    SchemaVersion = 1
    Type = 'Probe'; Operation = 'List'; OperationKind = 'Collection'
    HandlerStrategyId = 'Collection.Default'
    ApiVersion = 'v1.0'; Stability = 'Stable'; BetaReason = `$null
    Method = 'GET'; PathTemplate = '$PathTemplate'
    ResponseKind = 'Collection'; PagingStrategy = 'NextLink'
    RequestBodyKind = `$null; RequiredPagingHeaders = @()
    DeduplicationKey = 'id'; SupportsAll = `$true; SupportsDelta = `$false
    ReplayPolicy = 'Safe'; Condition = `$null; Reconciliation = `$null
    AdvancedQuery = @{ Supported = `$false }
    Concurrency = @{ Mode = 'None'; Header = `$null; Required = `$false; AllowWildcard = `$false }
    CredentialPolicy = 'GraphBearer'; AllowedHosts = @()
    RedirectPolicy = 'None'; IdentityRequirement = 'Verified'
    ResourceFamily = 'Probe.Family'; ThrottleClass = 'Read'
    SupportedAuthModes = @('Certificate')
    RequiredPermissions = @(@{ Type = 'Application'; Value = 'X.Read.All' })
    RequiredLicense = @(); SupportedClouds = @('Global')
}
"@
            return $file
        }
    }

    AfterAll {
        Remove-Item -LiteralPath $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'accepts a rooted host-relative template' {
        $file = New-DescriptorFile -PathTemplate '/deviceManagement/probes'
        { InModuleScope GraphKit -Parameters @{ P = $file } { param($P) Import-GraphOperationDescriptor -Path $P } } |
            Should -Not -Throw
    }

    It 'rejects <Why>' -ForEach @(
        @{ Why = 'a template with no leading slash'; Template = 'deviceManagement/probes'; Match = '*must start with*' }
        @{ Why = 'an absolute URL';                  Template = 'https://evil.example/x';   Match = '*host-relative*' }
    ) {
        $file = New-DescriptorFile -PathTemplate $Template
        { InModuleScope GraphKit -Parameters @{ P = $file } { param($P) Import-GraphOperationDescriptor -Path $P } } |
            Should -Throw -ExpectedMessage $Match
    }
}

Describe 'Review finding: evidence allowlist reaches past depth 1' {
    # The allowlist constrained top-level field NAMES only, and the credential regex
    # inspected names never values - so Counts/Notes were unconstrained escape hatches.

    It 'refuses a non-numeric Counts entry (a row in disguise)' {
        { InModuleScope GraphKit {
            New-GraphEvidenceSummary -Fields @{ ProfileId = 'ivy24'; Counts = @{ deviceName = 'LAPTOP-01' } }
        } } | Should -Throw -ExpectedMessage '*must be numeric*'
    }

    It 'accepts a numeric Counts rollup' {
        { InModuleScope GraphKit {
            New-GraphEvidenceSummary -Fields @{ ProfileId = 'ivy24'; Counts = @{ NonCompliant = 12 } }
        } } | Should -Not -Throw
    }

    It 'refuses a bearer token pasted into a note' {
        { InModuleScope GraphKit {
            New-GraphEvidenceSummary -Fields @{
                ProfileId = 'ivy24'
                Notes     = @('context: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9abcdefghij')
            }
        } } | Should -Throw -ExpectedMessage '*bearer token*'
    }

    It 'accepts an ordinary summary note' {
        { InModuleScope GraphKit {
            New-GraphEvidenceSummary -Fields @{ ProfileId = 'ivy24'; Notes = @('12 of 40 devices were non-compliant.') }
        } } | Should -Not -Throw
    }
}

Describe 'Review finding: the per-call connect timeout is honoured' {
    # ConnectTimeout is fixed when the handler is built, so one shared client silently
    # honoured only the FIRST caller's value while still accepting the parameter.

    It 'builds a distinct client per connect-timeout so the parameter is not ignored' {
        InModuleScope GraphKit {
            $a = Get-GraphHttpClient -ConnectTimeoutSeconds 10
            $b = Get-GraphHttpClient -ConnectTimeoutSeconds 30
            $again = Get-GraphHttpClient -ConnectTimeoutSeconds 10

            [object]::ReferenceEquals($a, $b) | Should -BeFalse -Because 'a different connect timeout needs a different handler'
            [object]::ReferenceEquals($a, $again) | Should -BeTrue -Because 'the same timeout must reuse its client so pooling survives'
        }
    }
}
