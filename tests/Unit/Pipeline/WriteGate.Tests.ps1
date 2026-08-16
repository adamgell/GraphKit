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
