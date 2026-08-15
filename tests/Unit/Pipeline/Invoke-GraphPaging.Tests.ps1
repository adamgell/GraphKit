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

    # Closures bind to this test file's session state, so the $script: references below resolve
    # here even when the module invokes the scriptblocks.
    $script:FakeTransport = {
        param([uri] $Uri, [string] $Method, [hashtable] $Headers, $Body)

        $script:RecordedHeaders.Add($Headers)
        $script:RecordedUris.Add($Uri.AbsoluteUri)

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
        param([object[]] $Rows, [AllowNull()] [string] $NextLink)

        [PSCustomObject]@{
            PSTypeName = 'GraphKit.OperationResult'
            Data       = @{ value = @($Rows); '@odata.nextLink' = $NextLink }
            Outcome    = 'Succeeded'
            Certainty  = 'Known'
            Telemetry  = @()
            Provenance = @{}
        }
    }

    function Reset-PagingState {
        $script:PageQueue.Clear()
        $script:RecordedHeaders.Clear()
        $script:RecordedUris.Clear()
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
