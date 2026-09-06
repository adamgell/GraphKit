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
        Cloud        = 'Global'
        GraphBaseUri = [uri] 'https://graph.microsoft.com/v1.0'
    }

    $script:Descriptor = @{
        Type                  = 'ManagedDevice'
        Operation             = 'List'
        Method                = 'GET'
        PagingStrategy        = 'NextLink'
        DeduplicationKey      = 'id'
        RequiredPagingHeaders = @(@{ Name = 'ConsistencyLevel'; Value = 'eventual' })
    }

    $script:PageQueue = [System.Collections.Generic.Queue[object]]::new()
    $script:RecordedHeaders = [System.Collections.Generic.List[object]]::new()
    $script:RecordedUris = [System.Collections.Generic.List[string]]::new()
    $script:RecordedDeadlineSeconds = [System.Collections.Generic.List[double]]::new()

    # Closures bind to this test file's session state, so the $script: references below resolve
    # here even when the module invokes the scriptblocks.
    $script:FakeTransport = {
        param(
            [uri] $Uri,
            [string] $Method,
            [hashtable] $Headers,
            $Body,
            [System.Threading.CancellationToken] $CancellationToken,
            [double] $DeadlineSeconds
        )

        $script:RecordedHeaders.Add($Headers)
        $script:RecordedUris.Add($Uri.AbsoluteUri)
        $script:RecordedDeadlineSeconds.Add($DeadlineSeconds)

        if ($script:PageQueue.Count -eq 0) {
            throw 'FakeTransport: no scripted page remains'
        }

        return $script:PageQueue.Dequeue()
    }

    $script:Factory = {
        param([uri] $Uri, [hashtable] $Descriptor)

        @{
            Uri     = $Uri
            Method  = 'GET'
            Headers = @{ 'ConsistencyLevel' = 'eventual' }
            Body    = $null
        }
    }

    function New-GraphPage {
        param(
            [object[]] $Rows,
            [AllowNull()] [string] $NextLink,
            [hashtable] $Provenance = @{}
        )

        [PSCustomObject]@{
            PSTypeName = 'GraphKit.OperationResult'
            Data       = @{ value = @($Rows); '@odata.nextLink' = $NextLink }
            Outcome    = 'Succeeded'
            Certainty  = 'Known'
            Telemetry  = @()
            Provenance = $Provenance
        }
    }

    function New-VerifiedPageProvenance {
        param(
            [guid] $TenantId = [guid] '00000000-0000-0000-0000-000000000001',
            [guid] $ActualTenantId = [guid] '00000000-0000-0000-0000-000000000001',
            [string] $IdentityState = 'VerifiedForToken',
            [AllowNull()] [object] $TokenFingerprint = 'paging-token-fingerprint',
            [AllowNull()] [object] $CredentialGeneration = 'paging-credential-generation',
            [string] $Cloud = 'Global'
        )

        $provenance = @{
            ProfileId            = 'paging-verified'
            TenantId             = $TenantId
            ActualTenantId       = $ActualTenantId
            IdentityState        = $IdentityState
            TokenFingerprint     = $TokenFingerprint
            CredentialGeneration = $CredentialGeneration
            Cloud                = $Cloud
            ApiVersion           = 'v1.0'
            ResourceFamily       = 'Intune.ManagedDevices'
        }
        foreach ($name in @('TokenFingerprint', 'CredentialGeneration')) {
            if ($null -eq $provenance[$name]) {
                $null = $provenance.Remove($name)
            }
        }
        return $provenance
    }

    function Reset-PagingState {
        $script:PageQueue.Clear()
        $script:RecordedHeaders.Clear()
        $script:RecordedUris.Clear()
        $script:RecordedDeadlineSeconds.Clear()
    }
}

Describe 'Invoke-GraphPaging' {
    It 'aggregates Data across pages' {
        Reset-PagingState
        $script:PageQueue.Enqueue((New-GraphPage @(@{ id = 'a' }) 'https://graph.microsoft.com/v1.0/page2'))
        $script:PageQueue.Enqueue((New-GraphPage @(@{ id = 'b' }) $null))

        $result = InModuleScope GraphKit -ArgumentList $script:Context, $script:Descriptor, $script:Factory, $script:FakeTransport {
            param($Context, $Descriptor, $Factory, $Transport)

            Invoke-GraphPaging `
                -Context $Context `
                -Descriptor $Descriptor `
                -FirstPageUri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices' `
                -RequestFactoryScript $Factory `
                -TransportScript $Transport
        }

        @($result.Data) | Should -HaveCount 2
        $result.Outcome | Should -Be 'Succeeded'
    }

    It 'requires every successful page of a Verified operation and carries the final verified provenance' {
        Reset-PagingState
        $tenantId = [guid] '00000000-0000-0000-0000-000000000001'
        $context = [pscustomobject] @{
            Cloud        = 'Global'
            GraphBaseUri = [uri] 'https://graph.microsoft.com/v1.0'
            TenantId     = $tenantId
            ClientId     = '00000000-0000-0000-0000-000000000010'
        }
        $descriptor = $script:Descriptor.Clone()
        $descriptor.IdentityRequirement = 'Verified'
        $firstProvenance = New-VerifiedPageProvenance
        $finalProvenance = New-VerifiedPageProvenance
        $finalProvenance.RetrievedUtc = [datetime] '2026-09-01T12:00:00Z'
        $script:PageQueue.Enqueue((New-GraphPage @(@{ id = 'a' }) 'https://graph.microsoft.com/v1.0/page2' $firstProvenance))
        $script:PageQueue.Enqueue((New-GraphPage @(@{ id = 'b' }) $null $finalProvenance))

        $result = InModuleScope GraphKit -ArgumentList $context, $descriptor, $script:Factory, $script:FakeTransport {
            param($Context, $Descriptor, $Factory, $Transport)
            Invoke-GraphPaging -Context $Context -Descriptor $Descriptor `
                -FirstPageUri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices' `
                -RequestFactoryScript $Factory -TransportScript $Transport
        }

        @($result.Data) | Should -HaveCount 2
        $result.Outcome | Should -BeExactly 'Succeeded'
        $result.Provenance.IdentityState | Should -BeExactly 'VerifiedForToken'
        $result.Provenance.TenantId | Should -Be $tenantId
        $result.Provenance.ActualTenantId | Should -Be $tenantId
        $result.Provenance.RetrievedUtc | Should -Be ([datetime] '2026-09-01T12:00:00Z')
        $result.Provenance.TokenFingerprint | Should -BeExactly 'paging-token-fingerprint'
        $result.Provenance.CredentialGeneration | Should -BeExactly 'paging-credential-generation'
        $result.Provenance.Cloud | Should -BeExactly 'Global'
    }

    It 'fails closed before collecting rows when any successful Verified page has <Case> provenance' -ForEach @(
        @{ Case = 'missing' }
        @{ Case = 'unverified' }
        @{ Case = 'wrong target' }
        @{ Case = 'wrong actual' }
    ) {
        Reset-PagingState
        $context = [pscustomobject] @{
            Cloud        = 'Global'
            GraphBaseUri = [uri] 'https://graph.microsoft.com/v1.0'
            TenantId     = [guid] '00000000-0000-0000-0000-000000000001'
            ClientId     = '00000000-0000-0000-0000-000000000010'
        }
        $descriptor = $script:Descriptor.Clone()
        $descriptor.IdentityRequirement = 'Verified'
        $pageProvenance = switch ($Case) {
            'missing'      { $null }
            'unverified'   { New-VerifiedPageProvenance -IdentityState NotAcquired }
            'wrong target' { New-VerifiedPageProvenance -TenantId ([guid] '00000000-0000-0000-0000-000000000002') }
            'wrong actual' { New-VerifiedPageProvenance -ActualTenantId ([guid] '00000000-0000-0000-0000-000000000002') }
        }
        $script:PageQueue.Enqueue((New-GraphPage @(@{ id = 'must-not-escape' }) 'https://graph.microsoft.com/v1.0/page2' $pageProvenance))
        $script:PageQueue.Enqueue((New-GraphPage @(@{ id = 'later' }) $null (New-VerifiedPageProvenance)))

        {
            InModuleScope GraphKit -ArgumentList $context, $descriptor, $script:Factory, $script:FakeTransport {
                param($Context, $Descriptor, $Factory, $Transport)
                Invoke-GraphPaging -Context $Context -Descriptor $Descriptor `
                    -FirstPageUri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices' `
                    -RequestFactoryScript $Factory -TransportScript $Transport
            }
        } | Should -Throw -ExpectedMessage '*VerifiedForToken tenant provenance*'

        $script:RecordedUris | Should -HaveCount 1
    }

    It 'rejects first-page Verified provenance with <Case> before retaining its rows' -ForEach @(
        @{ Case = 'missing fingerprint'; Override = @{ TokenFingerprint = $null } }
        @{ Case = 'blank fingerprint'; Override = @{ TokenFingerprint = '   ' } }
        @{ Case = 'missing generation'; Override = @{ CredentialGeneration = $null } }
        @{ Case = 'blank generation'; Override = @{ CredentialGeneration = "`t" } }
    ) {
        Reset-PagingState
        $context = [pscustomobject] @{
            Cloud        = 'Global'
            GraphBaseUri = [uri] 'https://graph.microsoft.com/v1.0'
            TenantId     = [guid] '00000000-0000-0000-0000-000000000001'
            ClientId     = '00000000-0000-0000-0000-000000000010'
        }
        $descriptor = $script:Descriptor.Clone()
        $descriptor.IdentityRequirement = 'Verified'
        $pageProvenance = New-VerifiedPageProvenance @Override
        $identityField = if ($Case -like '*fingerprint') { 'TokenFingerprint' } else { 'CredentialGeneration' }
        $pageProvenance.ContainsKey($identityField) | Should -Be ($Case -like 'blank *') `
            -Because 'missing and blank exact-token provenance are separate test inputs'
        $script:PageQueue.Enqueue((New-GraphPage @(@{ id = 'must-not-escape' }) $null $pageProvenance))

        $capture = InModuleScope GraphKit -ArgumentList $context, $descriptor, $script:Factory, $script:FakeTransport {
            param($Context, $Descriptor, $Factory, $Transport)
            $output = @()
            $failure = $null
            try {
                $output = @(Invoke-GraphPaging -Context $Context -Descriptor $Descriptor `
                    -FirstPageUri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices' `
                    -RequestFactoryScript $Factory -TransportScript $Transport)
            }
            catch {
                $failure = $_.Exception
            }
            [pscustomobject] @{ Output = $output; Failure = $failure }
        }

        $capture.Failure | Should -Not -BeNullOrEmpty
        $capture.Failure.Message | Should -BeLike '*exact-token provenance*'
        @($capture.Output) | Should -HaveCount 0
        $script:RecordedUris | Should -HaveCount 1
    }

    It 'rejects missing or cross-page exact-token provenance before returning any aggregate' -ForEach @(
        @{ Case = 'missing fingerprint'; Second = @{ TokenFingerprint = $null } }
        @{ Case = 'blank fingerprint'; Second = @{ TokenFingerprint = '   ' } }
        @{ Case = 'missing generation'; Second = @{ CredentialGeneration = $null } }
        @{ Case = 'blank generation'; Second = @{ CredentialGeneration = "`t" } }
        @{ Case = 'different fingerprint'; Second = @{ TokenFingerprint = 'paging-token-fingerprint-2' } }
        @{ Case = 'different generation'; Second = @{ CredentialGeneration = 'paging-credential-generation-2' } }
        @{ Case = 'different cloud'; Second = @{ Cloud = 'USGov' } }
    ) {
        Reset-PagingState
        $context = [pscustomobject] @{
            Cloud        = 'Global'
            GraphBaseUri = [uri] 'https://graph.microsoft.com/v1.0'
            TenantId     = [guid] '00000000-0000-0000-0000-000000000001'
            ClientId     = '00000000-0000-0000-0000-000000000010'
        }
        $descriptor = $script:Descriptor.Clone()
        $descriptor.IdentityRequirement = 'Verified'
        $secondProvenance = New-VerifiedPageProvenance @Second
        if ($Case -like 'missing *') {
            $identityField = if ($Case -like '*fingerprint') { 'TokenFingerprint' } else { 'CredentialGeneration' }
            $secondProvenance.ContainsKey($identityField) | Should -BeFalse `
                -Because 'missing and blank cross-page provenance are separate test inputs'
        }
        $script:PageQueue.Enqueue((New-GraphPage @(@{ id = 'must-not-escape' }) 'https://graph.microsoft.com/v1.0/page2' (New-VerifiedPageProvenance)))
        $script:PageQueue.Enqueue((New-GraphPage @(@{ id = 'also-must-not-escape' }) $null $secondProvenance))

        $capture = InModuleScope GraphKit -ArgumentList $context, $descriptor, $script:Factory, $script:FakeTransport {
            param($Context, $Descriptor, $Factory, $Transport)
            $output = @()
            $failure = $null
            try {
                $output = @(Invoke-GraphPaging -Context $Context -Descriptor $Descriptor `
                    -FirstPageUri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices' `
                    -RequestFactoryScript $Factory -TransportScript $Transport)
            }
            catch {
                $failure = $_.Exception
            }
            [pscustomobject] @{ Output = $output; Failure = $failure }
        }

        $capture.Failure | Should -Not -BeNullOrEmpty
        $capture.Failure.Message | Should -BeLike '*exact-token provenance*'
        @($capture.Output) | Should -HaveCount 0
        $script:RecordedUris | Should -HaveCount 2
    }

    It 'uses one inherited deadline across pages and sends nothing after the budget is exhausted' {
        Reset-PagingState
        $clock = [pscustomobject] @{ Value = [datetime] '2026-09-01T12:00:00Z' }
        $recorded = [System.Collections.Generic.List[double]]::new()
        $calls = [pscustomobject] @{ Count = 0 }
        $transport = {
            param($Uri, $Method, $Headers, $Body, $CancellationToken, [double] $DeadlineSeconds)
            $calls.Count++
            $recorded.Add($DeadlineSeconds)
            $clock.Value = $clock.Value.AddSeconds(5)
            return [pscustomobject] @{
                PSTypeName = 'GraphKit.OperationResult'
                Data       = @{ value = @(@{ id = 'must-not-escape' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/page2' }
                Outcome    = 'Succeeded'
                Certainty  = 'Known'
                Telemetry  = @()
                Provenance = @{}
            }
        }.GetNewClosure()
        $utcNow = { $clock.Value }.GetNewClosure()

        $result = InModuleScope GraphKit -ArgumentList $script:Context, $script:Descriptor, $script:Factory, $transport, $utcNow {
            param($Context, $Descriptor, $Factory, $Transport, $UtcNow)
            Invoke-GraphPaging -Context $Context -Descriptor $Descriptor `
                -FirstPageUri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices' `
                -RequestFactoryScript $Factory -TransportScript $Transport `
                -DeadlineSeconds 5 -UtcNow $UtcNow
        }

        $result.Outcome | Should -BeExactly 'DeadlineExpired'
        $result.Certainty | Should -BeExactly 'Indeterminate'
        @($result.Data) | Should -HaveCount 0
        $calls.Count | Should -Be 1
        $recorded | Should -HaveCount 1
        $recorded[0] | Should -BeGreaterThan 0
        $recorded[0] | Should -BeLessOrEqual 5
    }

    It 'sends nothing when request construction consumes the remaining collection deadline' {
        Reset-PagingState
        $clock = [pscustomobject] @{ Value = [datetime] '2026-09-01T12:00:00Z' }
        $calls = [pscustomobject] @{ Count = 0 }
        $factory = {
            param([uri] $Uri, [hashtable] $Descriptor)
            $clock.Value = $clock.Value.AddSeconds(5)
            return @{ Uri = $Uri; Method = 'GET'; Headers = @{}; Body = $null }
        }.GetNewClosure()
        $transport = {
            param($Uri, $Method, $Headers, $Body, $CancellationToken, [double] $DeadlineSeconds)
            $calls.Count++
            throw 'transport must not start after request construction exhausts the deadline'
        }.GetNewClosure()
        $utcNow = { $clock.Value }.GetNewClosure()

        $result = InModuleScope GraphKit -ArgumentList $script:Context, $script:Descriptor, $factory, $transport, $utcNow {
            param($Context, $Descriptor, $Factory, $Transport, $UtcNow)
            Invoke-GraphPaging -Context $Context -Descriptor $Descriptor `
                -FirstPageUri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices' `
                -RequestFactoryScript $Factory -TransportScript $Transport `
                -DeadlineSeconds 5 -UtcNow $UtcNow
        }

        $result.Outcome | Should -BeExactly 'DeadlineExpired'
        $result.Certainty | Should -BeExactly 'Indeterminate'
        @($result.Data) | Should -HaveCount 0
        $calls.Count | Should -Be 0
    }

    It 'does not start page two when the inherited remainder is below retry minimum resolution' {
        Reset-PagingState
        $clock = [pscustomobject] @{ Value = [datetime] '2026-09-01T12:00:00Z' }
        $calls = [pscustomobject] @{ Count = 0 }
        $transport = {
            param($Uri, $Method, $Headers, $Body, $CancellationToken, [double] $DeadlineSeconds)
            $calls.Count++
            if ($calls.Count -eq 1) {
                # Leave exactly 0.0005 seconds on the virtual collection clock.
                $clock.Value = $clock.Value.AddTicks(49995000)
                return [pscustomobject] @{
                    PSTypeName = 'GraphKit.OperationResult'
                    Data       = @{ value = @(@{ id = 'must-not-escape' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/page2' }
                    Outcome    = 'Succeeded'
                    Certainty  = 'Known'
                    Telemetry  = @()
                    Provenance = @{}
                }
            }
            throw 'page two transport must not start below retry deadline resolution'
        }.GetNewClosure()
        $utcNow = { $clock.Value }.GetNewClosure()

        $result = InModuleScope GraphKit -ArgumentList $script:Context, $script:Descriptor, $script:Factory, $transport, $utcNow {
            param($Context, $Descriptor, $Factory, $Transport, $UtcNow)
            Invoke-GraphPaging -Context $Context -Descriptor $Descriptor `
                -FirstPageUri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices' `
                -RequestFactoryScript $Factory -TransportScript $Transport `
                -DeadlineSeconds 5 -UtcNow $UtcNow
        }

        $result.Outcome | Should -BeExactly 'DeadlineExpired'
        $result.Certainty | Should -BeExactly 'Indeterminate'
        @($result.Data) | Should -HaveCount 0
        $calls.Count | Should -Be 1
    }

    It 'discards a terminal successful page that completes after the collection deadline' {
        Reset-PagingState
        $clock = [pscustomobject] @{ Value = [datetime] '2026-09-01T12:00:00Z' }
        $calls = [pscustomobject] @{ Count = 0 }
        $transport = {
            param($Uri, $Method, $Headers, $Body, $CancellationToken, [double] $DeadlineSeconds)
            $calls.Count++
            $clock.Value = $clock.Value.AddSeconds(6)
            return [pscustomobject] @{
                PSTypeName = 'GraphKit.OperationResult'
                Data       = @{ value = @(@{ id = 'late-row-must-not-escape' }); '@odata.nextLink' = $null }
                Outcome    = 'Succeeded'
                Certainty  = 'Known'
                Telemetry  = @()
                Provenance = @{}
            }
        }.GetNewClosure()
        $utcNow = { $clock.Value }.GetNewClosure()

        $result = InModuleScope GraphKit -ArgumentList $script:Context, $script:Descriptor, $script:Factory, $transport, $utcNow {
            param($Context, $Descriptor, $Factory, $Transport, $UtcNow)
            Invoke-GraphPaging -Context $Context -Descriptor $Descriptor `
                -FirstPageUri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices' `
                -RequestFactoryScript $Factory -TransportScript $Transport `
                -DeadlineSeconds 5 -UtcNow $UtcNow
        }

        $result.Outcome | Should -BeExactly 'DeadlineExpired'
        $result.Certainty | Should -BeExactly 'Indeterminate'
        @($result.Data) | Should -HaveCount 0
        $calls.Count | Should -Be 1
    }

    It 'discards earlier rows when a later page loses certainty' -ForEach @(
        @{ Outcome = 'Failed'; Certainty = 'Indeterminate' }
        @{ Outcome = 'Cancelled'; Certainty = 'Indeterminate' }
        @{ Outcome = 'DeadlineExpired'; Certainty = 'Indeterminate' }
    ) {
        Reset-PagingState
        $script:PageQueue.Enqueue((New-GraphPage @(@{ id = 'must-not-escape' }) 'https://graph.microsoft.com/v1.0/page2'))
        $script:PageQueue.Enqueue([pscustomobject] @{
            PSTypeName = 'GraphKit.OperationResult'
            Data       = @(@{ id = 'failed-page-row' })
            Outcome    = $Outcome
            Certainty  = $Certainty
            Telemetry  = @()
            Provenance = @{ IdentityState = 'NotAcquired' }
        })

        $result = InModuleScope GraphKit -ArgumentList $script:Context, $script:Descriptor, $script:Factory, $script:FakeTransport {
            param($Context, $Descriptor, $Factory, $Transport)
            Invoke-GraphPaging -Context $Context -Descriptor $Descriptor `
                -FirstPageUri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices' `
                -RequestFactoryScript $Factory -TransportScript $Transport
        }

        $result.Outcome | Should -BeExactly $Outcome
        $result.Certainty | Should -BeExactly $Certainty
        @($result.Data) | Should -HaveCount 0
        $script:RecordedUris | Should -HaveCount 2
    }

    It 'continues on an empty page that still carries a nextLink' {
        Reset-PagingState
        $script:PageQueue.Enqueue((New-GraphPage @() 'https://graph.microsoft.com/v1.0/page2'))
        $script:PageQueue.Enqueue((New-GraphPage @(@{ id = 'b' }) $null))

        $result = InModuleScope GraphKit -ArgumentList $script:Context, $script:Descriptor, $script:Factory, $script:FakeTransport {
            param($Context, $Descriptor, $Factory, $Transport)

            Invoke-GraphPaging `
                -Context $Context `
                -Descriptor $Descriptor `
                -FirstPageUri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices' `
                -RequestFactoryScript $Factory `
                -TransportScript $Transport
        }

        @($result.Data) | Should -HaveCount 1
        $result.Data[0].id | Should -Be 'b'
        $script:RecordedUris | Should -HaveCount 2
    }

    It 'repeats required headers on every page' {
        Reset-PagingState
        $script:PageQueue.Enqueue((New-GraphPage @(@{ id = 'a' }) 'https://graph.microsoft.com/v1.0/page2'))
        $script:PageQueue.Enqueue((New-GraphPage @(@{ id = 'b' }) $null))

        $null = InModuleScope GraphKit -ArgumentList $script:Context, $script:Descriptor, $script:Factory, $script:FakeTransport {
            param($Context, $Descriptor, $Factory, $Transport)

            Invoke-GraphPaging `
                -Context $Context `
                -Descriptor $Descriptor `
                -FirstPageUri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices' `
                -RequestFactoryScript $Factory `
                -TransportScript $Transport
        }

        $script:RecordedHeaders | Should -HaveCount 2
        $script:RecordedHeaders[0]['ConsistencyLevel'] | Should -Be 'eventual'
        $script:RecordedHeaders[1]['ConsistencyLevel'] | Should -Be 'eventual'
    }

    It 'deduplicates rows by the DeduplicationKey' {
        Reset-PagingState
        $script:PageQueue.Enqueue((New-GraphPage @(@{ id = 'a' }, @{ id = 'b' }) 'https://graph.microsoft.com/v1.0/page2'))
        $script:PageQueue.Enqueue((New-GraphPage @(@{ id = 'a' }, @{ id = 'c' }) $null))

        $result = InModuleScope GraphKit -ArgumentList $script:Context, $script:Descriptor, $script:Factory, $script:FakeTransport {
            param($Context, $Descriptor, $Factory, $Transport)

            Invoke-GraphPaging `
                -Context $Context `
                -Descriptor $Descriptor `
                -FirstPageUri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices' `
                -RequestFactoryScript $Factory `
                -TransportScript $Transport
        }

        @($result.Data) | Should -HaveCount 3
        ($result.Data | Where-Object { $_.id -eq 'a' }) | Should -HaveCount 1
    }

    It 'honours the page cap and warns' {
        Reset-PagingState
        $script:PageQueue.Enqueue((New-GraphPage @(@{ id = 'a' }) 'https://graph.microsoft.com/v1.0/page2'))
        $script:PageQueue.Enqueue((New-GraphPage @(@{ id = 'b' }) 'https://graph.microsoft.com/v1.0/page3'))
        $script:PageQueue.Enqueue((New-GraphPage @(@{ id = 'c' }) $null))

        # The call runs in module scope, so capture -WarningVariable inside the block: common
        # parameter variables do not propagate out of an InModuleScope block.
        $captured = InModuleScope GraphKit -ArgumentList $script:Context, $script:Descriptor, $script:Factory, $script:FakeTransport {
            param($Context, $Descriptor, $Factory, $Transport)

            $pageCapWarnings = $null
            $pagingResult = Invoke-GraphPaging `
                -Context $Context `
                -Descriptor $Descriptor `
                -FirstPageUri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices' `
                -RequestFactoryScript $Factory `
                -TransportScript $Transport `
                -MaxPages 1 `
                -WarningVariable pageCapWarnings

            [PSCustomObject]@{
                Result   = $pagingResult
                Warnings = @($pageCapWarnings)
            }
        }

        $result = $captured.Result
        @($result.Data) | Should -HaveCount 1
        ($captured.Warnings -join ';') | Should -Match 'page cap'
        $result.Outcome | Should -BeExactly 'Succeeded'
        $result.Certainty | Should -BeExactly 'Indeterminate'
        $result.Truncated | Should -BeTrue
    }

    It 'blocks a hostile nextLink authority before the next hop' {
        Reset-PagingState
        $script:PageQueue.Enqueue((New-GraphPage @(@{ id = 'a' }) 'https://evil.example.com/page2'))

        {
            InModuleScope GraphKit -ArgumentList $script:Context, $script:Descriptor, $script:Factory, $script:FakeTransport {
                param($Context, $Descriptor, $Factory, $Transport)

                Invoke-GraphPaging `
                    -Context $Context `
                    -Descriptor $Descriptor `
                    -FirstPageUri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices' `
                    -RequestFactoryScript $Factory `
                    -TransportScript $Transport
            }
        } | Should -Throw -ExpectedMessage '*evil.example.com*'
    }

    It 'stops and propagates a non-success page outcome' {
        Reset-PagingState
        $failed = [PSCustomObject]@{
            PSTypeName = 'GraphKit.OperationResult'
            Data       = @()
            Outcome    = 'Failed'
            Certainty  = 'Indeterminate'
            Telemetry  = @()
            Provenance = @{}
        }
        $script:PageQueue.Enqueue($failed)

        $result = InModuleScope GraphKit -ArgumentList $script:Context, $script:Descriptor, $script:Factory, $script:FakeTransport {
            param($Context, $Descriptor, $Factory, $Transport)

            Invoke-GraphPaging `
                -Context $Context `
                -Descriptor $Descriptor `
                -FirstPageUri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices' `
                -RequestFactoryScript $Factory `
                -TransportScript $Transport
        }

        $result.Outcome | Should -Be 'Failed'
        $result.Certainty | Should -Be 'Indeterminate'
    }
}
