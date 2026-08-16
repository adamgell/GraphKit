BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) { throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first.' }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force

    $script:catalog = @(Get-GraphOperation -List)
}

Describe 'The mutating-operation dry-run gate' {

    It 'exposes -WhatIf and -Confirm on the generic operation entry point' {
        # Before this, Invoke-GraphOperation - the one command that can execute ANY descriptor,
        # including mutating ones - had no ShouldProcess at all, while the module's own mutating
        # commands (Grant-GraphAppPermission, Remove-GraphTenant, Import-GraphLegacyProfile) all
        # declared it. A caller who reached for the standard PowerShell dry run got
        # "A parameter cannot be found that matches parameter name 'WhatIf'".
        $cmd = Get-Command Invoke-GraphOperation
        $cmd.Parameters.ContainsKey('WhatIf')  | Should -BeTrue
        $cmd.Parameters.ContainsKey('Confirm') | Should -BeTrue
    }

    It 'does not raise ConfirmImpact, so unattended writes still run without a console' {
        # A High impact would make every scheduled write block on a confirmation prompt that no
        # automation context can answer. -WhatIf is the deliverable here; interactive confirmation
        # stays opt-in via -Confirm.
        $meta = [System.Management.Automation.CommandMetadata]::new((Get-Command Invoke-GraphOperation))
        $meta.SupportsShouldProcess | Should -BeTrue
        $meta.ConfirmImpact | Should -Not -Be 'High'
    }

    Context 'what counts as mutating is declared, not inferred from the verb' {

        It 'treats every GET in the shipped catalog as non-mutating' {
            # The gate keys on ReplayPolicy. If a GET were ever marked non-Safe it would start
            # prompting on a read, and callers would learn to suppress the prompt everywhere.
            $badReads = @($script:catalog | Where-Object { $_.Method -eq 'GET' -and $_.ReplayPolicy -ne 'Safe' })
            $badReads | Should -BeNullOrEmpty -Because 'a GET that is not Safe would make the gate fire on a read'
        }

        It 'does not treat a report-generating POST as mutating' {
            # AppInstallSummaryReport.Get and DeviceReport.Export POST a request body to OBTAIN a
            # report. Gating on the HTTP verb would prompt for these, which is the exact reasoning
            # error the descriptor's ReplayPolicy exists to prevent.
            foreach ($name in @('AppInstallSummaryReport/Get', 'DeviceReport/Export')) {
                $parts = $name -split '/'
                $d = $script:catalog | Where-Object { $_.Type -eq $parts[0] -and $_.Operation -eq $parts[1] }
                $d | Should -Not -BeNullOrEmpty -Because "$name must exist for this test to mean anything"
                $d.Method | Should -Be 'POST'
                $d.ReplayPolicy | Should -Be 'Safe' -Because 'it obtains a report rather than changing anything'
            }
        }

        It 'treats the one real write in the catalog as mutating' {
            $d = $script:catalog | Where-Object { $_.Type -eq 'MobileApp' -and $_.Operation -eq 'Assign' }
            $d.ReplayPolicy | Should -Be 'NeverReplay'
            $d.ReplayPolicy | Should -Not -Be 'Safe' -Because 'this is what makes the gate fire'
        }
    }

    Context 'the gate actually suppresses the send' {

        BeforeAll {
            # A context whose transport would THROW if reached. Under -WhatIf nothing may reach it;
            # a gate that returns after sending would fail this rather than silently pass.
            $script:probeContext = InModuleScope GraphKit {
                [PSCustomObject]@{
                    ProfileId    = 'gate-probe'
                    GraphBaseUri = [uri] 'https://graph.microsoft.com'
                    TokenSource  = $null
                    TenantId     = [guid]::Empty
                }
            }
        }

        It 'sends nothing for a mutating operation under -WhatIf' {
            $sent = $false
            InModuleScope GraphKit -Parameters @{ Ctx = $script:probeContext } {
                param($Ctx)
                Mock Invoke-GraphHandlerStrategy { throw 'the gate let a mutating call through under -WhatIf' }
                Mock Test-GraphCredentialPolicy { $null }

                { Invoke-GraphOperation -Context $Ctx -Type MobileApp -Operation Assign `
                    -Parameters @{ id = '11111111-1111-1111-1111-111111111111'; Body = @{} } -WhatIf } |
                    Should -Not -Throw
            }
        }

        It 'still enforces credential policy under -WhatIf, so a dry run cannot report a false success' {
            # The gate sits AFTER validation on purpose. A -WhatIf that skipped the credential and
            # URI checks would happily "succeed" for a call that could never have run.
            InModuleScope GraphKit -Parameters @{ Ctx = $script:probeContext } {
                param($Ctx)
                $checked = $false
                Mock Invoke-GraphHandlerStrategy { throw 'must not execute' }
                Mock Test-GraphCredentialPolicy { $script:policyChecked = $true; $null }

                $script:policyChecked = $false
                Invoke-GraphOperation -Context $Ctx -Type MobileApp -Operation Assign `
                    -Parameters @{ id = '11111111-1111-1111-1111-111111111111'; Body = @{} } -WhatIf
                $script:policyChecked | Should -BeTrue -Because 'a dry run must still prove the call would be permitted'
            }
        }

        It 'does not gate a report-generating POST, exercising the gate rather than the data' {
            # This is the test that earns its place. The sibling assertions above check the
            # DESCRIPTOR fields, and a mutation swapping the gate from ReplayPolicy to the HTTP
            # verb left them all green - they could not see which signal the gate reads. This one
            # runs DeviceReport.Export (POST, ReplayPolicy Safe) under -WhatIf and requires it to
            # execute. Under a verb-based gate it would be suppressed and return nothing.
            InModuleScope GraphKit -Parameters @{ Ctx = $script:probeContext } {
                param($Ctx)
                Mock Test-GraphCredentialPolicy { $null }
                Mock Invoke-GraphHandlerStrategy {
                    [PSCustomObject]@{
                        Data = @('report-ran'); Outcome = 'Succeeded'; Certainty = 'Known'
                        Telemetry = @(); Provenance = @{}
                    }
                }

                $r = Invoke-GraphOperation -Context $Ctx -Type DeviceReport -Operation Export `
                        -Parameters @{ Body = @{ reportName = 'Devices' } } -WhatIf
                $r | Should -Not -BeNullOrEmpty -Because 'a POST that only obtains a report must not be gated'
            }
        }

        It 'leaves reads completely unaffected' {
            # The regression that would matter most: if the gate fired on reads, every existing
            # consumer - IHA, TenantPulse - would start returning nothing under -WhatIf.
            InModuleScope GraphKit -Parameters @{ Ctx = $script:probeContext } {
                param($Ctx)
                Mock Test-GraphCredentialPolicy { $null }
                # A full envelope, because Invoke-GraphOperation stamps Provenance on the result;
                # a thinner stub fails on the stamp rather than on the behaviour under test.
                Mock Invoke-GraphHandlerStrategy {
                    [PSCustomObject]@{
                        Data       = @('read-ran')
                        Outcome    = 'Succeeded'
                        Certainty  = 'Known'
                        Telemetry  = @()
                        Provenance = @{}
                    }
                }

                $r = Invoke-GraphOperation -Context $Ctx -Type ManagedDevice -Operation List -WhatIf
                $r | Should -Not -BeNullOrEmpty -Because 'a read is not gated, so -WhatIf must not suppress it'
            }
        }
    }
}

Describe 'Bodyless actions' {
    # Whether an action carries a body is declared by RequestBodyKind. Action.Default used to
    # demand one from every action, which was correct while MobileApp.Assign was the only action in
    # the catalog and silently excluded most of the write surface: Intune's device actions are
    # bodyless POSTs and deletes carry no body at all. Those descriptors could be written but never
    # executed - the strategy rejected them before a request was built.

    BeforeAll {
        $script:ctx = InModuleScope GraphKit {
            [PSCustomObject]@{
                ProfileId = 'bodyless-probe'; GraphBaseUri = [uri] 'https://graph.microsoft.com'
                TokenSource = $null; TenantId = [guid]::Empty
            }
        }
    }

    It 'executes an action that declares no body' {
        InModuleScope GraphKit -Parameters @{ Ctx = $script:ctx } {
            param($Ctx)
            $script:sentBody = 'unset'
            Mock Test-GraphCredentialPolicy { $null }
            Mock Invoke-GraphRetry {
                param($Context, $Descriptor, $Uri, $Method, $Headers, $Body, $CancellationToken)
                $script:sentBody = $Body
                [PSCustomObject]@{ Data = @(); Outcome = 'Succeeded'; Certainty = 'Known'; Telemetry = @(); Provenance = @{} }
            }

            $null = Invoke-GraphOperation -Context $Ctx -Type ManagedDevice -Operation SyncDevice `
                        -Parameters @{ id = 'dev-1' } -Confirm:$false
            $script:sentBody | Should -BeNullOrEmpty -Because 'a bodyless action must send no body'
        }
    }

    It 'rejects a Body supplied to an action that declares none' {
        # Dropping it silently would hide a real mismatch in the caller's intent, and Graph would
        # reject the request anyway with a less specific error.
        {
            InModuleScope GraphKit -Parameters @{ Ctx = $script:ctx } {
                param($Ctx)
                Mock Test-GraphCredentialPolicy { $null }
                Mock Invoke-GraphRetry { [PSCustomObject]@{ Data = @(); Outcome = 'Succeeded'; Certainty = 'Known'; Telemetry = @(); Provenance = @{} } }
                Invoke-GraphOperation -Context $Ctx -Type ManagedDevice -Operation SyncDevice `
                    -Parameters @{ id = 'dev-1'; Body = @{ unexpected = $true } } -Confirm:$false
            }
        } | Should -Throw -ExpectedMessage '*declares no request body*'
    }

    It 'still requires a body from an action that declares one' {
        {
            InModuleScope GraphKit -Parameters @{ Ctx = $script:ctx } {
                param($Ctx)
                Mock Test-GraphCredentialPolicy { $null }
                Mock Invoke-GraphRetry { [PSCustomObject]@{ Data = @(); Outcome = 'Succeeded'; Certainty = 'Known'; Telemetry = @(); Provenance = @{} } }
                Invoke-GraphOperation -Context $Ctx -Type DeviceCompliancePolicy -Operation Assign `
                    -Parameters @{ id = 'pol-1' } -Confirm:$false
            }
        } | Should -Throw -ExpectedMessage '*requires a request body*'
    }

    It 'gates both new writes behind -WhatIf' {
        foreach ($op in @(
            @{ T = 'ManagedDevice'; O = 'SyncDevice'; P = @{ id = 'dev-1' } }
            @{ T = 'DeviceCompliancePolicy'; O = 'Assign'; P = @{ id = 'pol-1'; Body = @{ assignments = @() } } }
        )) {
            InModuleScope GraphKit -Parameters @{ Ctx = $script:ctx; Op = $op } {
                param($Ctx, $Op)
                Mock Test-GraphCredentialPolicy { $null }
                Mock Invoke-GraphRetry { throw "the $($Op.T)/$($Op.O) write escaped the -WhatIf gate" }
                { Invoke-GraphOperation -Context $Ctx -Type $Op.T -Operation $Op.O -Parameters $Op.P -WhatIf } |
                    Should -Not -Throw
            }
        }
    }
}

Describe 'High-impact confirmation' {
    # ConfirmImpact is a property of the CMDLET, and Invoke-GraphOperation is one cmdlet serving
    # every descriptor, so it cannot vary per operation. Its default Medium against the default
    # $ConfirmPreference of High means ShouldProcess returns true WITHOUT PROMPTING - fine for an
    # assignment, not fine for a factory reset. Impact = 'High' adds ShouldContinue, which prompts
    # regardless of $ConfirmPreference, and -Force is the named automation opt-out.

    BeforeAll {
        $script:hiCtx = InModuleScope GraphKit {
            [PSCustomObject]@{
                ProfileId = 'impact-probe'; GraphBaseUri = [uri] 'https://graph.microsoft.com'
                TokenSource = $null; TenantId = [guid]::Empty
            }
        }
        $script:catalog = @(Get-GraphOperation -List)
    }

    It 'declares exactly one High-impact operation, and it is Wipe' {
        # If this count grows, someone added an irreversible operation. That should be a decision,
        # not a diff nobody read.
        $high = @($script:catalog | Where-Object { $_.Impact -eq 'High' })
        $high.Count | Should -Be 1
        "$($high[0].Type)/$($high[0].Operation)" | Should -Be 'ManagedDevice/Wipe'
    }

    It 'separates disruptive from destructive' {
        # Delete removes the Intune RECORD; the machine keeps working. Wipe erases the machine.
        # They read almost identically in a script, so the catalog carries the difference.
        foreach ($n in @('Retire', 'Delete')) {
            $d = $script:catalog | Where-Object { $_.Type -eq 'ManagedDevice' -and $_.Operation -eq $n }
            $d | Should -Not -BeNullOrEmpty
            $d.Impact | Should -Be 'Medium' -Because "$n is recoverable - the user re-enrolls"
        }
    }

    It 'requires a body for Wipe even though Graph would accept an empty one' {
        # keepUserData and keepEnrollmentData default to false server-side, so the empty body is
        # the MOST destructive call - and the one written by accident.
        $d = $script:catalog | Where-Object { $_.Type -eq 'ManagedDevice' -and $_.Operation -eq 'Wipe' }
        $d.RequestBodyKind | Should -Not -BeNullOrEmpty
    }

    It 'refuses to send a High-impact operation without -Force' {
        # The critical case, and it must FAIL rather than prompt. The first version of this gate
        # called ShouldContinue, which does not reliably throw in a non-interactive host - it
        # blocks on stdin. The test run hung past ten minutes. A wedged CI job is worse than a
        # failed one, so the gate is now a hard requirement with no prompt at all.
        {
            InModuleScope GraphKit -Parameters @{ Ctx = $script:hiCtx } {
                param($Ctx)
                Mock Test-GraphCredentialPolicy { $null }
                Mock Invoke-GraphHandlerStrategy { throw 'a High-impact operation was SENT without confirmation' }
                Invoke-GraphOperation -Context $Ctx -Type ManagedDevice -Operation Wipe `
                    -Parameters @{ id = 'dev-1'; Body = @{ keepUserData = $false } }
            }
        } | Should -Throw -ExpectedMessage '*-Force*'
    }

    It 'proceeds when -Force is given' {
        InModuleScope GraphKit -Parameters @{ Ctx = $script:hiCtx } {
            param($Ctx)
            $script:wipeSent = $false
            Mock Test-GraphCredentialPolicy { $null }
            Mock Invoke-GraphHandlerStrategy {
                $script:wipeSent = $true
                [PSCustomObject]@{ Data = @(); Outcome = 'Succeeded'; Certainty = 'Known'; Telemetry = @(); Provenance = @{} }
            }
            $null = Invoke-GraphOperation -Context $Ctx -Type ManagedDevice -Operation Wipe `
                        -Parameters @{ id = 'dev-1'; Body = @{ keepUserData = $false } } -Force
            $script:wipeSent | Should -BeTrue
        }
    }

    It 'still honours -WhatIf ahead of -Force, so a dry run of a wipe sends nothing' {
        # -Force must not become a way to skip the dry run. If these two ever swapped order,
        # "-WhatIf -Force" would wipe the device it claimed to be simulating.
        InModuleScope GraphKit -Parameters @{ Ctx = $script:hiCtx } {
            param($Ctx)
            Mock Test-GraphCredentialPolicy { $null }
            Mock Invoke-GraphHandlerStrategy { throw '-WhatIf was overridden by -Force' }
            { Invoke-GraphOperation -Context $Ctx -Type ManagedDevice -Operation Wipe `
                -Parameters @{ id = 'dev-1'; Body = @{ keepUserData = $false } } -WhatIf -Force } |
                Should -Not -Throw
        }
    }

    It 'does not gate a Medium-impact write behind confirmation' {
        # Retire is disruptive, not destructive. If Medium started prompting, every routine
        # remediation script would hang and someone would reach for -Force everywhere - which is
        # how the High gate gets neutered in practice.
        InModuleScope GraphKit -Parameters @{ Ctx = $script:hiCtx } {
            param($Ctx)
            $script:retireSent = $false
            Mock Test-GraphCredentialPolicy { $null }
            Mock Invoke-GraphHandlerStrategy {
                $script:retireSent = $true
                [PSCustomObject]@{ Data = @(); Outcome = 'Succeeded'; Certainty = 'Known'; Telemetry = @(); Provenance = @{} }
            }
            $null = Invoke-GraphOperation -Context $Ctx -Type ManagedDevice -Operation Retire -Parameters @{ id = 'dev-1' }
            $script:retireSent | Should -BeTrue -Because 'Medium impact must not require -Force'
        }
    }

    It 'rejects a descriptor claiming impact on a non-mutating operation' {
        $dir = Join-Path $TestDrive ([guid]::NewGuid()); $null = New-Item -ItemType Directory -Path $dir -Force
        $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
        $tpl = Get-Content (Join-Path $repoRoot 'source/Data/Operations/ManagedDevice.List.psd1') -Raw
        $path = Join-Path $dir 'Bad.List.psd1'
        ($tpl -replace "ReplayPolicy        = 'Safe'", "ReplayPolicy        = 'Safe'`n    Impact              = 'High'") |
            Set-Content -LiteralPath $path -Encoding utf8
        InModuleScope GraphKit -Parameters @{ Path = $path } {
            { Import-GraphOperationDescriptor -Path $Path } | Should -Throw -ExpectedMessage '*cannot be destructive*'
        }
    }
}

