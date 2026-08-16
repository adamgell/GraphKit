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
        IdentityState = 'VerifiedForToken'
    }

    $script:RecordedCalls = [System.Collections.Generic.List[object]]::new()

    # Closure bound to this test file's session state: $script:RecordedCalls resolves here even
    # when the module invokes the scriptblock as a transport delegate.
    $script:FakeTransport = {
        param([uri] $Uri, [string] $Method, [hashtable] $Headers, $Body, [System.Threading.CancellationToken] $CancellationToken)

        $script:RecordedCalls.Add([PSCustomObject]@{
                Uri     = $Uri.AbsoluteUri
                Method  = $Method
                Headers = $Headers
                Body    = $Body
            })

        [PSCustomObject]@{
            PSTypeName = 'GraphKit.OperationResult'
            Data       = @()
            Outcome    = 'Succeeded'
            Certainty  = 'Known'
            Telemetry  = @()
            Provenance = @{}
        }
    }

    function Reset-CallLog {
        $script:RecordedCalls.Clear()
    }
}

Describe 'Invoke-GraphHandlerStrategy registration' {
    It 'registers all four v1 strategies at import' {
        InModuleScope GraphKit {
            # Registration is idempotent and guaranteed on first strategy execution; the built
            # module concatenates private files alphabetically, so the import-time guard cannot
            # run before the registry exists. Ensure the module registers them, then resolve.
            $null = Ensure-GraphV1StrategiesRegistered

            Resolve-GraphHandlerStrategy -Id 'Collection.Default' | Should -Not -BeNullOrEmpty
            Resolve-GraphHandlerStrategy -Id 'Action.Default' | Should -Not -BeNullOrEmpty
            Resolve-GraphHandlerStrategy -Id 'Reconciliation.StableExternalKey' | Should -Not -BeNullOrEmpty
            Resolve-GraphHandlerStrategy -Id 'LongRunningJob.PollStatus' | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Invoke-GraphHandlerStrategy dispatch' {
    It 'Action.Default rejects a missing request body' {
        $descriptor = @{
            Type = 'MobileApp'; Operation = 'Assign'; OperationKind = 'Action'
            HandlerStrategyId = 'Action.Default'; Method = 'POST'
            PathTemplate = '/deviceAppManagement/mobileApps/{id}/assign'
            ApiVersion = 'v1.0'; AdvancedQuery = @{ Supported = $false }
            # RequestBodyKind is what declares that this action takes a body. These stubs called
            # themselves MobileApp/Assign while omitting it, so they asserted against a shape the
            # real descriptor does not have - the tests passed only because the strategy used to
            # demand a body from every action regardless of what the descriptor said.
            RequestBodyKind = 'MobileAppAssignmentSet'
            RequiredPagingHeaders = @(); Concurrency = @{ Mode = 'None'; Header = $null; Required = $false; AllowWildcard = $false }
        }

        {
            InModuleScope GraphKit -ArgumentList $script:Context, $descriptor, $script:FakeTransport {
                param($Context, $descriptor, $FakeTransport)

                Invoke-GraphHandlerStrategy -Context $Context -Descriptor $descriptor -Parameters @{ id = 'abc' } -Transport $FakeTransport
            }
        } | Should -Throw -ExpectedMessage '*requires a request body*'
    }

    It 'Action.Default posts the body with the descriptor method' {
        Reset-CallLog
        $descriptor = @{
            Type = 'MobileApp'; Operation = 'Assign'; OperationKind = 'Action'
            HandlerStrategyId = 'Action.Default'; Method = 'POST'
            PathTemplate = '/deviceAppManagement/mobileApps/{id}/assign'
            ApiVersion = 'v1.0'; AdvancedQuery = @{ Supported = $false }
            # RequestBodyKind is what declares that this action takes a body. These stubs called
            # themselves MobileApp/Assign while omitting it, so they asserted against a shape the
            # real descriptor does not have - the tests passed only because the strategy used to
            # demand a body from every action regardless of what the descriptor said.
            RequestBodyKind = 'MobileAppAssignmentSet'
            RequiredPagingHeaders = @(); Concurrency = @{ Mode = 'None'; Header = $null; Required = $false; AllowWildcard = $false }
        }

        $result = InModuleScope GraphKit -ArgumentList $script:Context, $descriptor, $script:FakeTransport {
            param($Context, $descriptor, $FakeTransport)

            Invoke-GraphHandlerStrategy `
                -Context $Context `
                -Descriptor $descriptor `
                -Parameters @{ id = 'abc'; Body = @{ assignments = @() } } `
                -Transport $FakeTransport
        }

        $result.Outcome | Should -Be 'Succeeded'
        $script:RecordedCalls | Should -HaveCount 1
        $script:RecordedCalls[0].Method | Should -Be 'POST'
        $script:RecordedCalls[0].Uri | Should -Match '/deviceAppManagement/mobileApps/abc/assign'
        $script:RecordedCalls[0].Body.assignments | Should -BeNullOrEmpty
    }

    It 'Collection.Default delegates paging for NextLink operations' {
        $descriptor = @{
            Type = 'ManagedDevice'; Operation = 'List'; OperationKind = 'Collection'
            HandlerStrategyId = 'Collection.Default'; Method = 'GET'
            PathTemplate = '/deviceManagement/managedDevices'; PagingStrategy = 'NextLink'
            DeduplicationKey = 'id'; RequiredPagingHeaders = @()
            ApiVersion = 'v1.0'; AdvancedQuery = @{ Supported = $true }
            Concurrency = @{ Mode = 'None'; Header = $null; Required = $false; AllowWildcard = $false }
        }

        $fakeEnvelope = [PSCustomObject]@{
            PSTypeName = 'GraphKit.OperationResult'
            Data       = @(@{ id = 'x' })
            Outcome    = 'Succeeded'
            Certainty  = 'Known'
            Telemetry  = @()
            Provenance = @{}
        }

        Mock Invoke-GraphPaging -ModuleName GraphKit { return $fakeEnvelope }

        $result = InModuleScope GraphKit -ArgumentList $script:Context, $descriptor, $script:FakeTransport {
            param($Context, $descriptor, $FakeTransport)

            Invoke-GraphHandlerStrategy -Context $Context -Descriptor $descriptor -Parameters @{} -Transport $FakeTransport
        }

        $result.Data | Should -Not -BeNullOrEmpty
        Should-Invoke Invoke-GraphPaging -ModuleName GraphKit -Times 1 -Exactly
    }

    It 'Reconciliation.StableExternalKey requires a Reconciliation block and stable key' {
        $descriptor = @{
            Type = 'Policy'; Operation = 'Create'; OperationKind = 'Action'
            HandlerStrategyId = 'Reconciliation.StableExternalKey'; Method = 'POST'
            PathTemplate = '/deviceManagement/configurationPolicies'
            ReplayPolicy = 'Reconciliable'; Reconciliation = $null
            ApiVersion = 'v1.0'; AdvancedQuery = @{ Supported = $false }
            # RequestBodyKind is what declares that this action takes a body. These stubs called
            # themselves MobileApp/Assign while omitting it, so they asserted against a shape the
            # real descriptor does not have - the tests passed only because the strategy used to
            # demand a body from every action regardless of what the descriptor said.
            RequestBodyKind = 'MobileAppAssignmentSet'
            RequiredPagingHeaders = @(); Concurrency = @{ Mode = 'None'; Header = $null; Required = $false; AllowWildcard = $false }
        }

        {
            InModuleScope GraphKit -ArgumentList $script:Context, $descriptor, $script:FakeTransport {
                param($Context, $descriptor, $FakeTransport)

                Invoke-GraphHandlerStrategy -Context $Context -Descriptor $descriptor -Parameters @{} -Transport $FakeTransport
            }
        } | Should -Throw -ExpectedMessage '*Reconciliation*'
    }

    It 'Reconciliation.StableExternalKey reads through the supplied transport only' {
        Reset-CallLog
        $descriptor = @{
            Type = 'Policy'; Operation = 'Create'; OperationKind = 'Action'
            HandlerStrategyId = 'Reconciliation.StableExternalKey'; Method = 'POST'
            PathTemplate = '/deviceManagement/configurationPolicies'
            ReplayPolicy = 'Reconciliable'
            Reconciliation = @{ StableExternalKey = 'displayName' }
            ApiVersion = 'v1.0'; AdvancedQuery = @{ Supported = $false }
            # RequestBodyKind is what declares that this action takes a body. These stubs called
            # themselves MobileApp/Assign while omitting it, so they asserted against a shape the
            # real descriptor does not have - the tests passed only because the strategy used to
            # demand a body from every action regardless of what the descriptor said.
            RequestBodyKind = 'MobileAppAssignmentSet'
            RequiredPagingHeaders = @(); Concurrency = @{ Mode = 'None'; Header = $null; Required = $false; AllowWildcard = $false }
        }

        $result = InModuleScope GraphKit -ArgumentList $script:Context, $descriptor, $script:FakeTransport {
            param($Context, $descriptor, $FakeTransport)

            Invoke-GraphHandlerStrategy `
                -Context $Context `
                -Descriptor $descriptor `
                -Parameters @{ displayName = 'policy-a' } `
                -Transport $FakeTransport `
                -IntendedState @{ displayName = 'policy-a' }
        }

        $script:RecordedCalls | Should -HaveCount 1
        $script:RecordedCalls[0].Method | Should -Be 'GET'
    }
}

Describe 'Get-GraphRequestHeaders' {
    It 'never attaches an Authorization header (the transport owns the bearer)' {
        $headers = InModuleScope GraphKit {
            Get-GraphRequestHeaders -Descriptor @{
                AdvancedQuery         = @{ Supported = $false }
                RequiredPagingHeaders = @()
                Concurrency           = @{ Mode = 'None'; Header = $null; Required = $false; AllowWildcard = $false }
            }
        }

        $headers.ContainsKey('Authorization') | Should -BeFalse
    }

    It 'emits ConsistencyLevel only when advanced query is supported' {
        $with = InModuleScope GraphKit {
            Get-GraphRequestHeaders -Descriptor @{
                AdvancedQuery         = @{ Supported = $true; ConsistencyLevel = 'eventual' }
                RequiredPagingHeaders = @()
                Concurrency           = @{ Mode = 'None'; Header = $null; Required = $false; AllowWildcard = $false }
            }
        }
        $with['ConsistencyLevel'] | Should -Be 'eventual'

        $without = InModuleScope GraphKit {
            Get-GraphRequestHeaders -Descriptor @{
                AdvancedQuery         = @{ Supported = $false }
                RequiredPagingHeaders = @()
                Concurrency           = @{ Mode = 'None'; Header = $null; Required = $false; AllowWildcard = $false }
            }
        }
        $without.ContainsKey('ConsistencyLevel') | Should -BeFalse
    }

    It 'repeats required paging headers' {
        $headers = InModuleScope GraphKit {
            Get-GraphRequestHeaders -Descriptor @{
                AdvancedQuery         = @{ Supported = $false }
                RequiredPagingHeaders = @(@{ Name = 'X-Custom'; Value = 'y' })
                Concurrency           = @{ Mode = 'None'; Header = $null; Required = $false; AllowWildcard = $false }
            }
        }

        $headers['X-Custom'] | Should -Be 'y'
    }
}

Describe 'Singleton.Default strategy' {

    BeforeAll {
        $script:SingletonDescriptor = @{
            Type              = 'ManagedDeviceSetting'
            Operation         = 'Get'
            OperationKind     = 'Singleton'
            HandlerStrategyId = 'Singleton.Default'
            ApiVersion        = 'beta'
            Method            = 'GET'
            PathTemplate      = '/deviceManagement/settings'
            PagingStrategy    = 'None'
            ResponseKind      = 'Json'
            CredentialPolicy  = 'GraphBearer'
            AdvancedQuery     = @{ Supported = $false }
            Concurrency       = @{ Mode = 'None'; Header = $null; Required = $false; AllowWildcard = $false }
        }
    }

    It 'is a known v1 strategy' {
        InModuleScope GraphKit {
            { Resolve-GraphHandlerStrategy -Id 'Singleton.Default' } | Should -Not -Throw
        }
    }

    It 'returns the response object without unwrapping a value property' {
        # This is the entire reason Singleton.Default exists rather than reusing
        # Collection.Default with paging off. A singleton that happens to carry its own
        # 'value' property would be silently replaced by that property under the collection
        # handler - the object would be swapped for one of its fields, with no error.
        $transport = {
            param([uri] $Uri, [string] $Method, [hashtable] $Headers, $Body, [System.Threading.CancellationToken] $CancellationToken)
            [PSCustomObject]@{
                PSTypeName = 'GraphKit.OperationResult'
                Data       = @{ 'value' = 'this is a scalar property, not a collection'; 'secureByDefault' = $true }
                Outcome    = 'Succeeded'
                Certainty  = 'Known'
                Telemetry  = @()
                Provenance = @{}
            }
        }

        $result = InModuleScope GraphKit -Parameters @{ D = $script:SingletonDescriptor; C = $script:Context; T = $transport } {
            Invoke-GraphHandlerStrategy -Context $C -Descriptor $D -Parameters @{} -Transport $T
        }

        $result.Outcome | Should -Be 'Succeeded'
        $result.Data | Should -BeOfType [System.Collections.IDictionary]
        $result.Data['secureByDefault'] | Should -BeTrue
        $result.Data['value'] | Should -Be 'this is a scalar property, not a collection'
    }

    It 'issues exactly one request and does not page' {
        $calls = [System.Collections.Generic.List[object]]::new()
        $transport = {
            param([uri] $Uri, [string] $Method, [hashtable] $Headers, $Body, [System.Threading.CancellationToken] $CancellationToken)
            $calls.Add($Uri.AbsoluteUri)
            [PSCustomObject]@{
                PSTypeName = 'GraphKit.OperationResult'
                Data       = @{ '@odata.nextLink' = 'https://graph.microsoft.com/beta/deviceManagement/settings?page=2' }
                Outcome    = 'Succeeded'
                Certainty  = 'Known'
                Telemetry  = @()
                Provenance = @{}
            }
        }.GetNewClosure()

        $null = InModuleScope GraphKit -Parameters @{ D = $script:SingletonDescriptor; C = $script:Context; T = $transport } {
            Invoke-GraphHandlerStrategy -Context $C -Descriptor $D -Parameters @{} -Transport $T
        }

        # A nextLink in a singleton response must not trigger paging.
        $calls.Count | Should -Be 1
        $calls[0] | Should -Be 'https://graph.microsoft.com/beta/deviceManagement/settings'
    }
}

Describe 'Descriptor-declared ResponseKind' {

    BeforeAll {
        # Intune's report endpoints return a JSON document under 'application/octet-stream'.
        # The transport classifies by Content-Type and correctly calls that binary, so the
        # caller got a byte dump where the descriptor promised Json. The descriptor is the
        # authority on operation behaviour, so it wins - but only ever to upgrade bytes that
        # actually sniff as JSON.
        $script:JsonBytes = [System.Text.Encoding]::UTF8.GetBytes('{"TotalRowCount":80,"Values":[]}')

        function New-ResultWithData {
            param($Data)
            [PSCustomObject]@{
                PSTypeName = 'GraphKit.OperationResult'
                Data       = $Data
                Outcome    = 'Succeeded'
                Certainty  = 'Known'
                Telemetry  = @()
                Provenance = @{}
            }
        }
    }

    It 'parses a byte[] body when the descriptor declares Json' {
        $out = InModuleScope GraphKit -Parameters @{ B = $script:JsonBytes } {
            ConvertTo-GraphDeclaredResponseKind -Result ([PSCustomObject]@{ Data = $B }) -Descriptor @{ ResponseKind = 'Json' }
        }
        $out.Data['TotalRowCount'] | Should -Be 80
    }

    It 'parses an Object[] of bytes, which is how the body actually arrives' {
        # Regression: the first version of this check tested only for [byte[]] and silently
        # missed every real response, because PowerShell unrolls an array returned through
        # the pipeline into Object[].
        # Built explicitly as object[]; piping an array to Should -BeOfType would unroll it
        # and assert on its first element instead of the array.
        [object[]] $asObjectArray = @($script:JsonBytes | ForEach-Object { $_ })
        ($asObjectArray -is [object[]]) | Should -BeTrue -Because 'the fixture must reproduce the unrolled shape'

        $out = InModuleScope GraphKit -Parameters @{ B = $asObjectArray } {
            ConvertTo-GraphDeclaredResponseKind -Result ([PSCustomObject]@{ Data = $B }) -Descriptor @{ ResponseKind = 'Json' }
        }
        $out.Data['TotalRowCount'] | Should -Be 80
    }

    It 'leaves a Binary descriptor untouched' {
        # DeviceReport.Export downloads a file. Sniffing globally would corrupt it.
        $out = InModuleScope GraphKit -Parameters @{ B = $script:JsonBytes } {
            ConvertTo-GraphDeclaredResponseKind -Result ([PSCustomObject]@{ Data = $B }) -Descriptor @{ ResponseKind = 'Binary' }
        }
        ($out.Data -is [byte[]]) | Should -BeTrue
    }

    It 'leaves non-JSON bytes alone even when the descriptor declares Json' {
        # Declared Json but the payload is not JSON: guessing further would replace a
        # recoverable payload with a wrong one.
        $notJson = [System.Text.Encoding]::UTF8.GetBytes('PK<binary zip content>')
        $out = InModuleScope GraphKit -Parameters @{ B = $notJson } {
            ConvertTo-GraphDeclaredResponseKind -Result ([PSCustomObject]@{ Data = $B }) -Descriptor @{ ResponseKind = 'Json' }
        }
        ($out.Data -is [byte[]]) | Should -BeTrue
    }

    It 'leaves an already-parsed body alone' {
        $out = InModuleScope GraphKit {
            ConvertTo-GraphDeclaredResponseKind -Result ([PSCustomObject]@{ Data = @{ already = 'parsed' } }) -Descriptor @{ ResponseKind = 'Json' }
        }
        $out.Data['already'] | Should -Be 'parsed'
    }
}
