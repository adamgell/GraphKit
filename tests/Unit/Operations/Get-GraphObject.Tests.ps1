BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    # Import the BUILT module (never dot-source source files: they would redefine module classes
    # and Add-Type types in test scope). Pester discovers tests per file, so each file imports it.
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built GraphKit module found under output/module/GraphKit; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force

    $script:Context = [PSCustomObject]@{
        Cloud         = 'Global'
        GraphBaseUri  = [uri] 'https://graph.microsoft.com'
        ProfileId     = 'ivy24'
        TenantId      = [guid] '00000000-0000-0000-0000-000000000001'
        IdentityState = 'VerifiedForToken'
    }

    function New-TestEnvelope {
        param(
            [object[]] $Data = @(),
            [string] $Outcome = 'Succeeded',
            [string] $Certainty = 'Known'
        )

        [PSCustomObject]@{
            PSTypeName = 'GraphKit.OperationResult'
            Data       = $Data
            Outcome    = $Outcome
            Certainty  = $Certainty
            Telemetry  = @()
            Provenance = $null
        }
    }

    function New-TestDescriptor {
        param(
            [string] $Type = 'MobileApp',
            [string] $Operation = 'List',
            [string] $PagingStrategy = 'NextLink'
        )

        @{
            Type                  = $Type
            Operation             = $Operation
            ApiVersion            = 'v1.0'
            ResourceFamily        = 'Intune.MobileApps'
            CredentialPolicy      = 'GraphBearer'
            AllowedHosts          = @()
            PagingStrategy        = $PagingStrategy
            Method                = 'GET'
            PathTemplate          = '/deviceAppManagement/mobileApps'
            RequiredPagingHeaders = @()
            DeduplicationKey      = 'id'
        }
    }

    # The retry engine's live path must never escape a unit test. A default throwing mock is
    # registered before the per-test mocks; tests exercise the paging or handler-strategy path
    # instead and never touch the transport.
    Mock Invoke-GraphRetry -ModuleName GraphKit {
        throw 'Invoke-GraphRetry must be mocked in this test.'
    }
}

Describe 'Get-GraphObject' {

    Context 'Row stamping' {
        It 'stamps every row with the type name and provenance fields' {
            Mock Get-GraphOperation -ModuleName GraphKit { New-TestDescriptor -Type 'MobileApp' -Operation 'List' }
            Mock Resolve-GraphUri -ModuleName GraphKit { [uri] 'https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps' }
            Mock Invoke-GraphPaging -ModuleName GraphKit {
                New-TestEnvelope -Data @(
                    @{ id = 'a1'; displayName = 'App One' }
                    @{ id = 'a2'; displayName = 'App Two' }
                )
            }

            $rows = @(Get-GraphObject -Context $script:Context -Type MobileApp)

            $rows.Count | Should -Be 2
            foreach ($row in $rows) {
                $row.PSObject.TypeNames | Should -Contain 'GraphKit.MobileApp'
                $row._Tenant | Should -Be 'ivy24'
                $row._GraphPath | Should -Be '/v1.0/deviceAppManagement/mobileApps'
                $row._ApiVersion | Should -Be 'v1.0'
                $row._RetrievedUtc | Should -BeOfType [datetime]
            }
        }

        It 'reads a single object (non-paging) through the handler strategy and stamps one row' {
            Mock Get-GraphOperation -ModuleName GraphKit { New-TestDescriptor -Type 'ManagedDevice' -Operation 'Get' -PagingStrategy 'None' }
            Mock Resolve-GraphUri -ModuleName GraphKit { [uri] 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/d1' }
            Mock Invoke-GraphHandlerStrategy -ModuleName GraphKit {
                New-TestEnvelope -Data @{ id = 'd1'; deviceName = 'PC1' }
            }
            Mock Invoke-GraphPaging -ModuleName GraphKit { throw 'unexpected paging call' }

            $rows = @(Get-GraphObject -Context $script:Context -Type ManagedDevice -Operation Get -Parameters @{ id = 'd1' })

            $rows.Count | Should -Be 1
            $rows[0].deviceName | Should -Be 'PC1'
            $rows[0].PSObject.TypeNames | Should -Contain 'GraphKit.ManagedDevice'
            Should-Invoke Invoke-GraphHandlerStrategy -ModuleName GraphKit -Times 1 -Exactly
            Should-NotInvoke Invoke-GraphPaging -ModuleName GraphKit
        }
    }

    Context 'Failure semantics' {
        It 'throws on a Failed/Indeterminate outcome, naming both the Outcome and Certainty' {
            Mock Get-GraphOperation -ModuleName GraphKit { New-TestDescriptor -Type 'MobileApp' -Operation 'List' }
            Mock Resolve-GraphUri -ModuleName GraphKit { [uri] 'https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps' }
            Mock Invoke-GraphPaging -ModuleName GraphKit {
                New-TestEnvelope -Outcome 'Failed' -Certainty 'Indeterminate'
            }

            {
                Get-GraphObject -Context $script:Context -Type MobileApp
            } | Should -Throw -ExpectedMessage '*Failed*Indeterminate*'
        }
    }

    Context 'Output modes' {
        It 'returns the envelope only with -PassThruResult and never emits rows' {
            Mock Get-GraphOperation -ModuleName GraphKit { New-TestDescriptor -Type 'MobileApp' -Operation 'List' }
            Mock Resolve-GraphUri -ModuleName GraphKit { [uri] 'https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps' }
            Mock Invoke-GraphPaging -ModuleName GraphKit {
                New-TestEnvelope -Data @(@{ id = 'a1'; displayName = 'App One' })
            }

            $result = Get-GraphObject -Context $script:Context -Type MobileApp -PassThruResult

            $result.PSObject.TypeNames | Should -Contain 'GraphKit.OperationResult'
            $result.Outcome | Should -Be 'Succeeded'
            $result.Provenance.ProfileId | Should -Be 'ivy24'
            $result.Provenance.ApiVersion | Should -Be 'v1.0'
            $result.Provenance.ResourceFamily | Should -Be 'Intune.MobileApps'
        }

        It 'emits no rows for an empty result set' {
            Mock Get-GraphOperation -ModuleName GraphKit { New-TestDescriptor -Type 'MobileApp' -Operation 'List' }
            Mock Resolve-GraphUri -ModuleName GraphKit { [uri] 'https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps' }
            Mock Invoke-GraphPaging -ModuleName GraphKit { New-TestEnvelope -Data @() }

            $rows = @(Get-GraphObject -Context $script:Context -Type MobileApp)

            $rows.Count | Should -Be 0
        }
    }

    Context 'Paging' {
        It 'pages a NextLink collection through Invoke-GraphPaging and honours -PageCap' {
            Mock Get-GraphOperation -ModuleName GraphKit { New-TestDescriptor -Type 'MobileApp' -Operation 'List' }
            Mock Resolve-GraphUri -ModuleName GraphKit { [uri] 'https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps' }
            Mock Invoke-GraphPaging -ModuleName GraphKit {
                New-TestEnvelope -Data @(
                    @{ id = 'p1'; displayName = 'Page One App' }
                    @{ id = 'p2'; displayName = 'Page Two App' }
                )
            }
            Mock Invoke-GraphHandlerStrategy -ModuleName GraphKit { throw 'unexpected strategy call' }

            $rows = @(Get-GraphObject -Context $script:Context -Type MobileApp -PageCap 7)

            $rows.Count | Should -Be 2
            $rows[0].PSObject.TypeNames | Should -Contain 'GraphKit.MobileApp'
            Should-Invoke Invoke-GraphPaging -ModuleName GraphKit -Times 1 -Exactly -ParameterFilter { $MaxPages -eq 7 }
            Should-NotInvoke Invoke-GraphHandlerStrategy -ModuleName GraphKit
        }
    }

    Context 'Descriptor resolution' {
        It 'defaults -Operation to List when only -Type is given' {
            Mock Get-GraphOperation -ModuleName GraphKit { New-TestDescriptor -Type 'ManagedDevice' -Operation 'List' }
            Mock Resolve-GraphUri -ModuleName GraphKit { [uri] 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices' }
            Mock Invoke-GraphPaging -ModuleName GraphKit { New-TestEnvelope -Data @() }

            Get-GraphObject -Context $script:Context -Type ManagedDevice | Out-Null

            Should-Invoke Get-GraphOperation -ModuleName GraphKit -Times 1 -Exactly -ParameterFilter { $Type -eq 'ManagedDevice' -and $Operation -eq 'List' }
        }
    }

    Context 'Input validation' {
        It 'rejects supplying both -Context and -ProfileId' {
            {
                Get-GraphObject -Context $script:Context -ProfileId ivy24 -Type MobileApp
            } | Should -Throw -ExpectedMessage '*not both*'
        }
    }
}

Describe 'Register-GraphArgumentCompleter' {

    It 'registers (or re-registers) without throwing at import' {
        { InModuleScope GraphKit { Register-GraphArgumentCompleter } } | Should -Not -Throw
    }

    It 'completes -Type from the catalog type set' {
        $results = InModuleScope GraphKit {
            @(& $script:GraphTypeCompleter 'Get-GraphObject' 'Type' '' $null @{}) | ForEach-Object { $_.CompletionText }
        }

        foreach ($expected in @('MobileApp', 'ManagedDevice', 'DeviceConfiguration', 'DeviceReport')) {
            $results | Should -Contain $expected
        }
    }

    It 'completes -Operation filtered by the already-bound -Type' {
        $results = InModuleScope GraphKit {
            @(& $script:GraphOperationCompleter 'Get-GraphObject' 'Operation' '' $null @{ Type = 'ManagedDevice' }) | ForEach-Object { $_.CompletionText }
        }

        $results | Should -Contain 'List'
        $results | Should -Contain 'Get'
    }
}
