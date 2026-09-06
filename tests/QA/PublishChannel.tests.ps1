BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:channelPublisher = Join-Path $script:repoRoot 'scripts/Publish-GraphKitPackage.ps1'
    $script:galleryPublisher = Join-Path $script:repoRoot 'scripts/Publish-GraphKitToGallery.ps1'
    $script:publishers = @($script:channelPublisher, $script:galleryPublisher)

    function Get-ScriptCommandMetadata {
        param([Parameter(Mandatory)] [string] $Path)
        return Get-Command -Name $Path -CommandType ExternalScript
    }

    function Get-ScriptAst {
        param([Parameter(Mandatory)] [string] $Path)
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref] $tokens, [ref] $errors)
        @($errors).Count | Should -Be 0
        return $ast
    }
}

Describe 'GraphKit publisher release-proof boundary' -Tag 'QA' {
    It 'removes every test-proof bypass from the channel publisher' {
        $command = Get-ScriptCommandMetadata -Path $script:channelPublisher
        $command.Parameters.Keys | Should -Not -Contain 'SkipTestProof'
        $command.Parameters.Keys | Should -Not -Contain 'TestResultPath'
    }

    It 'requires a canonical proof for both publishers' {
        foreach ($path in $script:publishers) {
            $command = Get-ScriptCommandMetadata -Path $path
            $command.Parameters.Keys | Should -Contain 'ProofPath'
            $command.Parameters['ProofPath'].Attributes.Mandatory | Should -Contain $true
        }
    }

    It 'makes both publishers report-only unless the named Publish switch is present' {
        foreach ($path in $script:publishers) {
            $command = Get-ScriptCommandMetadata -Path $path
            $command.Parameters.Keys | Should -Contain 'Publish'
            $command.Parameters['Publish'].ParameterType | Should -Be ([switch])

            $ast = Get-ScriptAst -Path $path
            $source = $ast.Extent.Text
            $source | Should -Match '(?s)Test-GraphKitReleaseProof\.ps1.*if\s*\(\s*-not\s+\$Publish\s*\)'
            $source | Should -Match 'report-only|Nothing was published'
        }
    }

    It 'requires normal ShouldProcess authorization on both outward paths' {
        foreach ($path in $script:publishers) {
            $command = Get-ScriptCommandMetadata -Path $path
            $command.Parameters.Keys | Should -Contain 'WhatIf'
            (Get-Content -LiteralPath $path -Raw) | Should -Match '\$PSCmdlet\.ShouldProcess\('
        }
    }

    It 'uses the verifier-owned package snapshot for every publish command' {
        foreach ($path in $script:publishers) {
            $source = Get-Content -LiteralPath $path -Raw
            $source | Should -Match 'PackageSnapshotPath'
            $source | Should -Match '\$verified\.PackageSnapshotPath'
        }
    }

    It 'keeps the PSGallery API key out of the command line and reads it securely' {
        $command = Get-ScriptCommandMetadata -Path $script:galleryPublisher
        $command.Parameters.Keys | Should -Not -Contain 'ApiKey'
        $source = Get-Content -LiteralPath $script:galleryPublisher -Raw
        $source | Should -Match "Read-Host\s+'[^']*API key'\s+-AsSecureString"
    }
}
