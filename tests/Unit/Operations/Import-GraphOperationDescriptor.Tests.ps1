BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw "No built GraphKit module found under '$repoRoot/output/module/GraphKit'. Run './build.ps1 -Tasks build' first."
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force -ErrorAction Stop

    # The descriptor catalog ships beside the built module's root .psm1.
    $script:DataDir = (Resolve-Path (Join-Path $built.FullName 'Data/Operations')).ProviderPath

    $script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("graphkit-desc-$([guid]::NewGuid().ToString('N'))")
    New-Item -ItemType Directory -Path $script:TempDir -Force | Out-Null
    # Serialize a value as a PSD1 literal. Test-only; descriptors are never round-tripped
    # through this in production.
    function ConvertTo-Psd1Literal {
        param($Value)

        if ($null -eq $Value) { return '$null' }
        if ($Value -is [bool]) { return $(if ($Value) { '$true' } else { '$false' }) }
        if ($Value -is [int] -or $Value -is [long]) { return [string]$Value }
        if ($Value -is [string]) { return "'" + ($Value -replace "'", "''") + "'" }
        if ($Value -is [System.Array]) {
            $items = @($Value | ForEach-Object { ConvertTo-Psd1Literal $_ })
            if ($items.Count -eq 0) { return '@()' }
            return '@(' + ($items -join ', ') + ')'
        }
        if ($Value -is [hashtable]) {
            $entries = @()
            foreach ($key in ($Value.Keys | Sort-Object)) {
                $entries += "$key = $(ConvertTo-Psd1Literal $Value[$key])"
            }
            if ($entries.Count -eq 0) { return '@{}' }
            return '@{ ' + ($entries -join '; ') + ' }'
        }
        throw "Unsupported literal type: $($Value.GetType().FullName)"
    }

    function New-TestDescriptorFile {
        param(
            [Parameter(Mandatory)]
            [hashtable] $Descriptor
        )

        $lines = @('@{')
        foreach ($key in ($Descriptor.Keys | Sort-Object)) {
            $lines += "    $key = $(ConvertTo-Psd1Literal $Descriptor[$key])"
        }
        $lines += '}'

        $path = Join-Path $script:TempDir ("desc-$([guid]::NewGuid().ToString('N')).psd1")
        Set-Content -LiteralPath $path -Value ($lines -join [Environment]::NewLine) -Encoding utf8
        return $path
    }

    # Builds a fully valid descriptor hashtable (a clone-able base for negative tests).
    function New-ValidDescriptor {
        return @{
            SchemaVersion       = 1
            Type                = 'TestType'
            Operation           = 'TestOp'
            OperationKind       = 'Action'
            HandlerStrategyId   = 'Action.Default'
            ApiVersion          = 'v1.0'
            Stability           = 'Stable'
            BetaReason          = $null
            Method              = 'POST'
            PathTemplate        = '/test/{id}'
            RequestBodyKind     = 'TestBody'
            ResponseKind        = 'NoContent'
            PagingStrategy      = 'None'
            RequiredPagingHeaders = @()
            DeduplicationKey    = $null
            SupportsAll         = $false
            SupportsDelta       = $false
            ReplayPolicy        = 'NeverReplay'
            Condition           = $null
            Reconciliation      = $null
            AdvancedQuery       = @{ Supported = $false }
            Concurrency         = @{ Mode = 'None'; Header = $null; Required = $false; AllowWildcard = $false }
            CredentialPolicy    = 'GraphBearer'
            AllowedHosts        = @()
            RedirectPolicy      = 'None'
            IdentityRequirement = 'Verified'
            ResourceFamily      = 'Test.Family'
            ThrottleClass       = 'Write'
            SupportedAuthModes  = @('Certificate')
            RequiredPermissions = @( @{ Type = 'Application'; Value = 'Test.Read.All' } )
            RequiredLicense     = @('Test License')
            SupportedClouds     = @('Global')
        }
    }

    # Writes a descriptor to a temp .psd1, imports it, and returns the validation error
    # message (or $null if it loaded cleanly).
    function Get-DescriptorError {
        param([Parameter(Mandatory)][string] $Path)

        return InModuleScope GraphKit -Parameters @{ Path = $Path } -ScriptBlock {
            param([string] $Path)

            try {
                $null = Import-GraphOperationDescriptor -Path $Path
                return $null
            }
            catch {
                return $_.Exception.Message
            }
        }
    }
}

AfterAll {
    if ($script:TempDir -and (Test-Path -LiteralPath $script:TempDir)) {
        Remove-Item -LiteralPath $script:TempDir -Recurse -Force
    }
}

Describe 'Import-GraphOperationDescriptor' {

    Context 'Real descriptors' {
        It 'loads MobileApp.Assign and round-trips the normative fields' {
            $d = InModuleScope GraphKit -Parameters @{ Path = (Join-Path $script:DataDir 'MobileApp.Assign.psd1') } -ScriptBlock {
                param([string] $Path)

                Import-GraphOperationDescriptor -Path $Path
            }

            $d['SchemaVersion'] | Should -Be 1
            $d['Type'] | Should -Be 'MobileApp'
            $d['Operation'] | Should -Be 'Assign'
            $d['OperationKind'] | Should -Be 'Action'
            $d['HandlerStrategyId'] | Should -Be 'Action.Default'
            $d['PagingStrategy'] | Should -Be 'None'
            $d['ReplayPolicy'] | Should -Be 'NeverReplay'
            $d['IdentityRequirement'] | Should -Be 'Verified'
            $d['Concurrency']['Mode'] | Should -Be 'None'
            $d['Concurrency'].ContainsKey('Header') | Should -BeTrue
            $d['Concurrency'].ContainsKey('Required') | Should -BeTrue
            $d['Concurrency'].ContainsKey('AllowWildcard') | Should -BeTrue
            # A deliberate tripwire, not a brittle assertion: it forces anyone adding a descriptor
        # field to come here and say so. 32 -> 33 when the optional 'Impact' field was added for
        # the write gate.
        $d.Keys.Count | Should -Be 33
        }

        It 'loads ManagedDevice.List with NextLink paging fields' {
            $d = InModuleScope GraphKit -Parameters @{ Path = (Join-Path $script:DataDir 'ManagedDevice.List.psd1') } -ScriptBlock {
                param([string] $Path)

                Import-GraphOperationDescriptor -Path $Path
            }

            $d['Type'] | Should -Be 'ManagedDevice'
            $d['OperationKind'] | Should -Be 'Collection'
            $d['HandlerStrategyId'] | Should -Be 'Collection.Default'
            $d['PagingStrategy'] | Should -Be 'NextLink'
            $d['DeduplicationKey'] | Should -Be 'id'
            $d['ReplayPolicy'] | Should -Be 'Safe'
            $d['ThrottleClass'] | Should -Be 'Read'
            $d['ResourceFamily'] | Should -Be 'Intune.ManagedDevices'
            $d['SupportedClouds'] | Should -Contain 'USGovDoD'
        }

        It 'loads DeviceReport.Export as a LongRunningJob' {
            $d = InModuleScope GraphKit -Parameters @{ Path = (Join-Path $script:DataDir 'DeviceReport.Export.psd1') } -ScriptBlock {
                param([string] $Path)

                Import-GraphOperationDescriptor -Path $Path
            }

            $d['Type'] | Should -Be 'DeviceReport'
            $d['OperationKind'] | Should -Be 'LongRunningJob'
            $d['HandlerStrategyId'] | Should -Be 'LongRunningJob.PollStatus'
            $d['Method'] | Should -Be 'POST'
            $d['ResponseKind'] | Should -Be 'Json'
            $d['ResourceFamily'] | Should -Be 'Intune.Reporting'
            $d['ThrottleClass'] | Should -Be 'Write'
        }
    }

    Context 'SchemaVersion' {
        It 'refuses a newer SchemaVersion' {
            $d = New-ValidDescriptor
            $d['SchemaVersion'] = 2
            $path = New-TestDescriptorFile $d

            $err = Get-DescriptorError $path

            $err | Should -Match ([regex]::Escape($path))
            $err | Should -Match 'newer than the supported version 1'
        }

        It 'rejects a non-integer SchemaVersion' {
            $d = New-ValidDescriptor
            $d['SchemaVersion'] = 'one'
            $path = New-TestDescriptorFile $d

            Get-DescriptorError $path | Should -Match "Field 'SchemaVersion' must be an integer"
        }
    }

    Context 'Required fields' {
        It 'rejects a missing field, naming the file and the missing key' {
            $d = New-ValidDescriptor
            $d.Remove('ResourceFamily')
            $path = New-TestDescriptorFile $d

            $err = Get-DescriptorError $path

            $err | Should -Match ([regex]::Escape($path))
            $err | Should -Match "Missing required field 'ResourceFamily'"
        }
    }

    Context 'Enum validation' {
        It 'rejects an invalid OperationKind' {
            $d = New-ValidDescriptor
            $d['OperationKind'] = 'Bogus'
            $path = New-TestDescriptorFile $d

            Get-DescriptorError $path | Should -Match "Field 'OperationKind' must be one of"
        }

        It 'rejects an invalid ThrottleClass' {
            $d = New-ValidDescriptor
            $d['ThrottleClass'] = 'Furious'
            $path = New-TestDescriptorFile $d

            Get-DescriptorError $path | Should -Match "Field 'ThrottleClass' must be one of"
        }
    }

    Context 'Cross-field rules' {
        It 'rejects CredentialPolicy None with an empty AllowedHosts' {
            $d = New-ValidDescriptor
            $d['CredentialPolicy'] = 'None'
            $d['AllowedHosts'] = @()
            $path = New-TestDescriptorFile $d

            Get-DescriptorError $path | Should -Match "CredentialPolicy 'None' requires a non-empty AllowedHosts"
        }

        It 'rejects CredentialPolicy None with a non-HTTPS allowed host' {
            $d = New-ValidDescriptor
            $d['CredentialPolicy'] = 'None'
            $d['AllowedHosts'] = @('http://reports.internal')
            $path = New-TestDescriptorFile $d

            Get-DescriptorError $path | Should -Match 'HTTPS-only AllowedHosts'
        }

        It 'rejects BetaPreferred without a BetaReason' {
            $d = New-ValidDescriptor
            $d['Stability'] = 'BetaPreferred'
            $d['BetaReason'] = $null
            $path = New-TestDescriptorFile $d

            Get-DescriptorError $path | Should -Match "Stability 'BetaPreferred' requires a non-empty BetaReason"
        }

        It 'rejects Reconciliable without a Reconciliation block' {
            $d = New-ValidDescriptor
            $d['ReplayPolicy'] = 'Reconciliable'
            $d['Reconciliation'] = $null
            $path = New-TestDescriptorFile $d

            Get-DescriptorError $path | Should -Match "ReplayPolicy 'Reconciliable' requires a non-empty Reconciliation block"
        }

        It 'rejects Conditional without a Condition block' {
            $d = New-ValidDescriptor
            $d['ReplayPolicy'] = 'Conditional'
            $d['Condition'] = $null
            $path = New-TestDescriptorFile $d

            Get-DescriptorError $path | Should -Match "ReplayPolicy 'Conditional' requires a Condition block"
        }

        It 'rejects beta ApiVersion with Stability Stable' {
            $d = New-ValidDescriptor
            $d['ApiVersion'] = 'beta'
            $d['Stability'] = 'Stable'
            $path = New-TestDescriptorFile $d

            Get-DescriptorError $path | Should -Match "ApiVersion 'beta' requires a beta-aware Stability"
        }

        It 'rejects AllowUnverifiedRead with a non-Read ThrottleClass' {
            $d = New-ValidDescriptor
            $d['IdentityRequirement'] = 'AllowUnverifiedRead'
            $d['ThrottleClass'] = 'Write'
            $d['ReplayPolicy'] = 'Safe'
            $path = New-TestDescriptorFile $d

            Get-DescriptorError $path | Should -Match "IdentityRequirement 'AllowUnverifiedRead' requires ThrottleClass 'Read'"
        }

        It 'rejects AllowUnverifiedRead with a non-Safe ReplayPolicy' {
            $d = New-ValidDescriptor
            $d['IdentityRequirement'] = 'AllowUnverifiedRead'
            $d['ThrottleClass'] = 'Read'
            $d['ReplayPolicy'] = 'NeverReplay'
            $path = New-TestDescriptorFile $d

            Get-DescriptorError $path | Should -Match "requires ReplayPolicy 'Safe'"
        }

        It 'rejects NextLink with a null DeduplicationKey' {
            $d = New-ValidDescriptor
            $d['PagingStrategy'] = 'NextLink'
            $d['DeduplicationKey'] = $null
            $path = New-TestDescriptorFile $d

            Get-DescriptorError $path | Should -Match "PagingStrategy 'NextLink' requires a non-empty DeduplicationKey"
        }
    }

    Context 'Handler strategy ID' {
        It 'rejects an unknown strategy ID' {
            $d = New-ValidDescriptor
            $d['HandlerStrategyId'] = 'Collection.Fancy'
            $path = New-TestDescriptorFile $d

            Get-DescriptorError $path | Should -Match 'not a known v1 strategy'
        }

        It 'rejects a wrong OperationKind prefix' {
            $d = New-ValidDescriptor
            $d['HandlerStrategyId'] = 'Collection.Default'
            $d['OperationKind'] = 'Action'
            $path = New-TestDescriptorFile $d

            Get-DescriptorError $path | Should -Match "kind prefix 'Collection'"
        }
    }
}
