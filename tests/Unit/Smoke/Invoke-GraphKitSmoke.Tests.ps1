BeforeAll {
    $script:smokeScript = (Resolve-Path (Join-Path $PSScriptRoot '../../../scripts/Invoke-GraphKitSmoke.ps1')).ProviderPath
    . $script:smokeScript

    function New-TestTransport {
        param(
            [System.Collections.Generic.List[string]] $Log,
            [hashtable] $Overrides = @{}
        )

        return {
            param(
                [string] $Kind,
                [hashtable] $Payload
            )

            $Log.Add($Kind)

            if ($Overrides.ContainsKey($Kind)) {
                return $Overrides[$Kind]
            }

            switch ($Kind) {
                'ManagedDeviceList' { return [PSCustomObject]@{ Outcome = 'Succeeded'; Certainty = 'Known'; Data = @(@{ id = 'device-1' }, @{ id = 'device-2' }) } }
                'AppAssignments'    { return [PSCustomObject]@{ Outcome = 'Succeeded'; Certainty = 'Known'; Data = @(@{ id = 'a1'; target = @{ groupId = 'g1' } }) } }
                'Assign'            { return [PSCustomObject]@{ Outcome = 'Succeeded'; Certainty = 'Known'; Data = $null } }
                'Revert'            { return [PSCustomObject]@{ Outcome = 'Succeeded'; Certainty = 'Known'; Data = $null } }
                default             { throw "unexpected transport kind '$Kind'" }
            }
        }.GetNewClosure()
    }

    function New-FailedEnvelope {
        param([string] $Outcome = 'Failed', [string] $Certainty = 'Known')
        return [PSCustomObject]@{ Outcome = $Outcome; Certainty = $Certainty; Data = $null }
    }
}

Describe 'Test-GraphKitSmokeDigest' {

    It 'accepts a matching digest case-insensitively' {
        { Test-GraphKitSmokeDigest -ExpectedHash 'ABC123' -ActualHash 'abc123' -PackagePath '/tmp/pkg.nupkg' } |
            Should -Not -Throw
    }

    It 'rejects a mismatched digest naming both hashes' {
        { Test-GraphKitSmokeDigest -ExpectedHash '1111111111111111111111111111111111111111111111111111111111111111' `
                -ActualHash '2222222222222222222222222222222222222222222222222222222222222222' -PackagePath '/tmp/pkg.nupkg' } |
            Should -Throw -ExpectedMessage '*1111111111111111111111111111111111111111111111111111111111111111*2222222222222222222222222222222222222222222222222222222222222222*'
    }

    It 'rejects an empty expected digest' {
        { Test-GraphKitSmokeDigest -ExpectedHash '' -ActualHash 'abc' } |
            Should -Throw -ExpectedMessage '*empty*'
    }
}

Describe 'Invoke-GraphKitSmokeFlow' {

    It 'executes read, capture, assign and revert through the transport in order' {
        $log = [System.Collections.Generic.List[string]]::new()
        $trace = [System.Collections.Generic.List[string]]::new()
        $transport = New-TestTransport -Log $log
        $context = [PSCustomObject]@{ ProfileId = 'ivy24' }

        $summary = Invoke-GraphKitSmokeFlow -Context $context -AppId ([guid]::NewGuid()) `
            -TestGroupId ([guid]::NewGuid()) -Transport $transport -Trace $trace

        ($log -join ',') | Should -Be 'ManagedDeviceList,AppAssignments,Assign,Revert'
        ($trace -join ',') | Should -Be 'read,capture,assign,revert'
        $summary.Mutation.Applied | Should -BeTrue
        $summary.Mutation.Reverted | Should -BeTrue
        $summary.CleanupState | Should -Be 'Reverted'
        $summary.ReadOutcome.Outcome | Should -Be 'Succeeded'
        $summary.ReadOutcome.DeviceCount | Should -Be 2
        $summary.Profile | Should -Be 'ivy24'
    }

    It 'reverts in the finally block even when the mutation assertion fails' {
        $log = [System.Collections.Generic.List[string]]::new()
        $overrides = @{ 'Assign' = (New-FailedEnvelope -Outcome 'Failed' -Certainty 'Indeterminate') }
        $transport = New-TestTransport -Log $log -Overrides $overrides
        $context = [PSCustomObject]@{ ProfileId = 'ivy24' }

        { Invoke-GraphKitSmokeFlow -Context $context -AppId ([guid]::NewGuid()) -TestGroupId ([guid]::NewGuid()) -Transport $transport } |
            Should -Throw -ExpectedMessage '*MUTATION*'

        # The assign was attempted and the finally still reverted, after the failed assertion.
        ($log -join ',') | Should -Be 'ManagedDeviceList,AppAssignments,Assign,Revert'
    }

    It 'still runs the finally cleanup when the read step fails' {
        $log = [System.Collections.Generic.List[string]]::new()
        $trace = [System.Collections.Generic.List[string]]::new()
        $overrides = @{ 'ManagedDeviceList' = (New-FailedEnvelope -Outcome 'Failed' -Certainty 'Known') }
        $transport = New-TestTransport -Log $log -Overrides $overrides
        $context = [PSCustomObject]@{ ProfileId = 'ivy24' }

        { Invoke-GraphKitSmokeFlow -Context $context -AppId ([guid]::NewGuid()) -TestGroupId ([guid]::NewGuid()) `
                -Transport $transport -Trace $trace } |
            Should -Throw -ExpectedMessage '*READ*'

        # No mutation was attempted, but the finally still recorded its cleanup decision.
        ($log -join ',') | Should -Be 'ManagedDeviceList'
        $trace | Should -Contain 'cleanup-skip'
    }

    It 'reports revert failure without masking it as success' {
        $log = [System.Collections.Generic.List[string]]::new()
        $overrides = @{ 'Revert' = (New-FailedEnvelope -Outcome 'Failed' -Certainty 'Known') }
        $transport = New-TestTransport -Log $log -Overrides $overrides
        $context = [PSCustomObject]@{ ProfileId = 'ivy24' }

        $summary = Invoke-GraphKitSmokeFlow -Context $context -AppId ([guid]::NewGuid()) `
            -TestGroupId ([guid]::NewGuid()) -Transport $transport

        $summary.Mutation.Applied | Should -BeTrue
        $summary.Mutation.Reverted | Should -BeFalse
        $summary.CleanupState | Should -Be 'RevertFailed'
    }
}

Describe 'Protect-GraphKitSmokeSummary' {

    It 'redacts every GUID-shaped value (tenant ids, app ids) to REDACTED' {
        $summary = [ordered]@{
            Profile  = 'ivy24'
            TenantId = '11111111-2222-3333-4444-555555555555'
            AppId    = ([guid]::NewGuid()).ToString()
            Nested   = [ordered]@{ ActualTenantId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' }
        }

        $redacted = Protect-GraphKitSmokeSummary -InputObject $summary
        $json = $redacted | ConvertTo-Json -Depth 6 -Compress

        $json | Should -Not -Match '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
        $json | Should -Match 'REDACTED'
        $redacted.Profile | Should -Be 'ivy24'
    }

    It 'leaves non-GUID values untouched' {
        $summary = @{ Profile = 'ivy24'; Count = 42; Notes = 'no secret here' }

        $redacted = Protect-GraphKitSmokeSummary -InputObject $summary

        $redacted.Count | Should -Be 42
        $redacted.Notes | Should -Be 'no secret here'
        $redacted.Profile | Should -Be 'ivy24'
    }
}
