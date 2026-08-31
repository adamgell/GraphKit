<#
    Phase 1.1 gate: the BUILT module, imported in a clean process.

    In-source testing cannot catch these. A module that works from source still fails once
    packaged when non-code assets are missing from build.yaml CopyPaths, or when a format
    file is packaged but never registered via FormatsToProcess. Both are silent: operation
    data appears absent and default views simply never apply.

    Run:  ./build.ps1 -Tasks test
#>

BeforeDiscovery {
    $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:BuiltBase = Get-ChildItem -Path (Join-Path $repoRoot 'output/module/GraphKit') -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
}

Describe 'Built module' -Skip:($null -eq $script:BuiltBase) {

    BeforeAll {
        $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        $script:BuiltBase = Get-ChildItem -Path (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
            Sort-Object Name -Descending | Select-Object -First 1
        $script:Manifest = Join-Path $script:BuiltBase.FullName 'GraphKit.psd1'
    }

    Context 'Packaging' {
        It 'produced a manifest' {
            Test-Path $script:Manifest | Should -BeTrue
        }

        It 'packaged <Path> (CopyPaths)' -ForEach @(
            @{ Path = 'Data/Operations' }
            @{ Path = 'Formats/GraphKit.Format.ps1xml' }
            @{ Path = 'en-US' }
        ) {
            Test-Path (Join-Path $script:BuiltBase.FullName $Path) | Should -BeTrue -Because 'missing CopyPaths entries vanish silently from the package'
        }

        It 'declares both always-required runtime dependencies' {
            $d = Import-PowerShellDataFile $script:Manifest
            $names = @($d.RequiredModules | ForEach-Object { if ($_ -is [hashtable]) { $_.ModuleName } else { $_ } })
            $names | Should -Contain 'Microsoft.Graph.Authentication'
            $names | Should -Contain 'Microsoft.PowerShell.SecretManagement'
        }

        It 'registers the format file via FormatsToProcess' {
            # CopyPaths packages it; only FormatsToProcess makes the views apply.
            (Import-PowerShellDataFile $script:Manifest).FormatsToProcess |
                Should -Contain 'Formats/GraphKit.Format.ps1xml'
        }

        It 'declares the PowerShell 7.4 floor' {
            (Import-PowerShellDataFile $script:Manifest).PowerShellVersion | Should -Be '7.4'
        }
    }

    Context 'Clean-process import' {
        BeforeAll {
            # A fresh pwsh: no modules already loaded, nothing inherited from this session.
            $script:Probe = pwsh -NoProfile -Command "
                Import-Module '$($script:Manifest)' -ErrorAction Stop
                `$views = (Get-FormatData -TypeName 'GraphKit.OperationResult' -ErrorAction SilentlyContinue)
                `$dataDir = Join-Path (Split-Path '$($script:Manifest)') 'Data/Operations'
                `$ops = @(Get-ChildItem `$dataDir -Filter *.psd1 -ErrorAction SilentlyContinue)
                [pscustomobject]@{
                    Imported  = `$true
                    ViewCount = @(`$views).Count
                    OpCount   = `$ops.Count
                    OpLoads   = [bool](`$ops | ForEach-Object { Import-PowerShellDataFile `$_.FullName })
                } | ConvertTo-Json -Compress
            " 2>&1 | Select-Object -Last 1 | ConvertFrom-Json
        }

        It 'imports in a fresh process' {
            $script:Probe.Imported | Should -BeTrue
        }

        It 'registers the GraphKit.OperationResult view' {
            $script:Probe.ViewCount | Should -BeGreaterThan 0 -Because 'packaged-but-unregistered format files fail exactly here'
        }

        It 'ships at least one operation descriptor' {
            $script:Probe.OpCount | Should -BeGreaterThan 0
        }

        It 'operation descriptors load as pure data' {
            # Import-PowerShellDataFile executes nothing: descriptors must stay data-only.
            $script:Probe.OpLoads | Should -BeTrue
        }
    }
}
