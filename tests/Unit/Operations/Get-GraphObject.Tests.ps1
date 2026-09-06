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
        ClientId      = '00000000-0000-0000-0000-000000000010'
        IdentityState = 'VerifiedForToken'
        TokenSource   = [PSCustomObject]@{ AuthMode = 'Certificate' }
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
            [string] $PagingStrategy = 'NextLink',
            [string[]] $SupportedAuthModes = @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')
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
            SupportedAuthModes    = $SupportedAuthModes
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

        It 'retains validated paged transport provenance when the context still says NotAcquired' {
            $context = [PSCustomObject]@{}
            foreach ($property in $script:Context.PSObject.Properties) {
                $context | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value
            }
            $context.IdentityState = 'NotAcquired'

            $script:pagedTransportProvenance = @{
                ProfileId            = 'ivy24'
                TenantId             = $context.TenantId
                ActualTenantId       = $context.TenantId
                ApiVersion           = 'v1.0'
                ResourceFamily       = 'Intune.MobileApps'
                RetrievedUtc         = [datetime] '2026-09-01T12:00:00Z'
                IdentityState        = 'VerifiedForToken'
                TokenFingerprint     = 'transport-fingerprint'
                CredentialGeneration = 'transport-generation'
                Cloud                = 'Global'
            }

            Mock Get-GraphOperation -ModuleName GraphKit {
                $descriptor = New-TestDescriptor -Type 'MobileApp' -Operation 'List'
                $descriptor.IdentityRequirement = 'Verified'
                return $descriptor
            }
            Mock Resolve-GraphUri -ModuleName GraphKit {
                [uri] 'https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps'
            }
            Mock Invoke-GraphPaging -ModuleName GraphKit {
                $envelope = New-TestEnvelope -Data @(@{ id = 'a1'; displayName = 'App One' })
                $envelope.Provenance = $script:pagedTransportProvenance
                return $envelope
            }

            $result = Get-GraphObject -Context $context -Type MobileApp -PassThruResult

            [object]::ReferenceEquals($result.Provenance, $script:pagedTransportProvenance) | Should -BeTrue
            $result.Provenance.IdentityState | Should -BeExactly 'VerifiedForToken'
            $result.Provenance.TenantId | Should -Be $context.TenantId
            $result.Provenance.ActualTenantId | Should -Be $context.TenantId
            $result.Provenance.RetrievedUtc | Should -Be ([datetime] '2026-09-01T12:00:00Z')
            $result.Provenance.TokenFingerprint | Should -BeExactly 'transport-fingerprint'
            $result.Provenance.CredentialGeneration | Should -BeExactly 'transport-generation'
            $result.Provenance.Cloud | Should -BeExactly 'Global'
            $result.Provenance.Keys | Should -Not -Contain 'ClientId'
            $result.Provenance.Keys | Should -Not -Contain 'ClientScopeFingerprint'
            $context.IdentityState | Should -BeExactly 'NotAcquired'
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

        It 'forwards the pager inherited remaining deadline into the retry attempt' {
            $script:retryDeadlineSeconds = $null
            $script:retryBoundParameters = $null
            $script:transportParameterNames = $null
            Mock Get-GraphOperation -ModuleName GraphKit { New-TestDescriptor -Type 'MobileApp' -Operation 'List' }
            Mock Resolve-GraphUri -ModuleName GraphKit { [uri] 'https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps' }
            Mock Invoke-GraphRetry -ModuleName GraphKit {
                param($DeadlineSeconds)
                $script:retryBoundParameters = @{} + $PSBoundParameters
                $script:retryDeadlineSeconds = [double] $DeadlineSeconds
                New-TestEnvelope -Data @()
            }
            Mock Invoke-GraphPaging -ModuleName GraphKit {
                param($Context, $Descriptor, $FirstPageUri, $RequestFactoryScript, $TransportScript)
                $script:transportParameterNames = @(
                    $TransportScript.Ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }
                )
                & $TransportScript $FirstPageUri 'GET' @{} $null `
                    ([System.Threading.CancellationToken]::None) 17.25
            }

            InModuleScope GraphKit -ArgumentList $script:Context {
                param($Context)
                Get-GraphObject -Context $Context -Type MobileApp -PassThruResult | Out-Null
            }

            $script:transportParameterNames | Should -Contain 'DeadlineSeconds'
            $script:retryBoundParameters.Keys | Should -Contain 'DeadlineSeconds'
            $script:retryDeadlineSeconds | Should -Be 17.25
            Should-Invoke Invoke-GraphRetry -ModuleName GraphKit -Times 1 -Exactly -ParameterFilter {
                [double] $DeadlineSeconds -eq 17.25
            }
        }
    }

    Context 'Descriptor resolution' {
        It 'rejects a descriptor that does not support the context auth mode before paging' {
            $context = [PSCustomObject]@{}
            foreach ($property in $script:Context.PSObject.Properties) {
                $context | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value
            }
            $context.TokenSource = [PSCustomObject]@{ AuthMode = 'BearerToken' }

            Mock Get-GraphOperation -ModuleName GraphKit {
                New-TestDescriptor -Type 'ManagedDevice' -Operation 'List' -SupportedAuthModes @('Certificate')
            }
            Mock Resolve-GraphUri -ModuleName GraphKit { throw 'URI resolution must not run' }
            Mock Invoke-GraphPaging -ModuleName GraphKit { throw 'paging must not run' }

            {
                Get-GraphObject -Context $context -Type ManagedDevice
            } | Should -Throw -ExpectedMessage "*does not support auth mode 'BearerToken'*"

            Should-NotInvoke Resolve-GraphUri -ModuleName GraphKit
            Should-NotInvoke Invoke-GraphPaging -ModuleName GraphKit
        }

        It 'permits an injected Provider context outside persisted auth-mode policy' {
            $context = [PSCustomObject]@{}
            foreach ($property in $script:Context.PSObject.Properties) {
                $context | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value
            }
            $context.TokenSource = [PSCustomObject]@{ AuthMode = 'Provider' }

            Mock Get-GraphOperation -ModuleName GraphKit {
                New-TestDescriptor -Type 'ManagedDevice' -Operation 'List' -SupportedAuthModes @('Certificate')
            }
            Mock Resolve-GraphUri -ModuleName GraphKit {
                [uri] 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices'
            }
            Mock Invoke-GraphPaging -ModuleName GraphKit { New-TestEnvelope -Data @() }

            Get-GraphObject -Context $context -Type ManagedDevice | Out-Null

            Should-Invoke Invoke-GraphPaging -ModuleName GraphKit -Times 1 -Exactly
        }

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

Describe 'Get-GraphObject failure carries the status code' {

    # Reported by a downstream consumer after a live run: on a failed read the HTTP status was
    # recorded in telemetry but unreachable from the thrown error, because the throw was a bare
    # string. A consumer could not tell permission-denied from any other failure without
    # re-issuing the whole request through -PassThruResult to read a number it had already been
    # given - against a customer tenant.
    #
    # Tested against the private builder rather than through Get-GraphObject. Driving it end to
    # end needs a context, a token source with a working Acquire, and a transport, and the
    # dispatch runs through a scriptblock built before a Pester mock applies - so a mock on the
    # handler intercepts nothing and the "unit" test silently issues a REAL request, then
    # asserts against whatever the tenant returned. That is how six iterations of this test
    # passed a live 401 off as a staged 403.

    BeforeDiscovery {
        $script:cases = @(
            @{ Status = 403; Expected = 'PermissionDenied'; Why = 'permission-denied must be distinguishable, so a consumer can report Skipped rather than Failed' }
            @{ Status = 401; Expected = 'AuthenticationError'; Why = 'a token problem is the operator''s to fix, not a missing scope' }
            @{ Status = 404; Expected = 'ObjectNotFound'; Why = 'absent is not failed' }
            @{ Status = 429; Expected = 'LimitsExceeded'; Why = 'throttling is retryable; a generic failure is not' }
            @{ Status = 503; Expected = 'ResourceUnavailable'; Why = 'server-side and transient' }
            @{ Status = 400; Expected = 'InvalidResult'; Why = 'the default for anything unclassified' }
        )
    }

    It 'maps HTTP <Status> to <Expected>' -ForEach $script:cases {
        $category = InModuleScope GraphKit -Parameters @{ Status = $Status } {
            $result = [PSCustomObject]@{
                Outcome   = 'Failed'
                Certainty = 'Known'
                Telemetry = @([PSCustomObject]@{ Attempt = 1; StatusCode = $Status; GraphErrorCode = 'SomeCode' })
            }
            (New-GraphOperationFailureRecord -Result $result -Type 'T' -Operation 'List').CategoryInfo.Category
        }
        [string] $category | Should -Be $Expected -Because $Why
    }

    It 'puts the status and Graph error code in the message and the envelope on TargetObject' {
        $record = InModuleScope GraphKit {
            $result = [PSCustomObject]@{
                Outcome   = 'Failed'
                Certainty = 'Known'
                Telemetry = @([PSCustomObject]@{ Attempt = 1; StatusCode = 403; GraphErrorCode = 'AccessDenied' })
            }
            New-GraphOperationFailureRecord -Result $result -Type 'ConditionalAccessPolicy' -Operation 'List'
        }

        $record.Exception.Message | Should -BeLike '*HTTP 403*'
        $record.Exception.Message | Should -BeLike "*Graph error 'AccessDenied'*"
        $record.FullyQualifiedErrorId | Should -Be 'GraphKit.OperationFailed.403'
        # The envelope must survive onto the error, or telemetry is lost with the exception.
        $record.TargetObject.Outcome | Should -Be 'Failed'
        @($record.TargetObject.Telemetry)[-1].StatusCode | Should -Be 403
    }

    It 'still produces a usable record when there is no telemetry at all' {
        # A failure before any attempt (deadline expired while waiting on the throttle gate)
        # leaves no telemetry. The record must still build rather than throw while reporting.
        $record = InModuleScope GraphKit {
            $result = [PSCustomObject]@{ Outcome = 'DeadlineExpired'; Certainty = 'Indeterminate'; Telemetry = @() }
            New-GraphOperationFailureRecord -Result $result -Type 'T' -Operation 'List'
        }
        $record.FullyQualifiedErrorId | Should -Be 'GraphKit.OperationFailed.0'
        $record.Exception.Message | Should -BeLike '*DeadlineExpired*'
        $record.Exception.Message | Should -Not -BeLike '*HTTP*' -Because 'no attempt was made, so no status should be claimed'
    }
}
