BeforeAll {
    # These guard against damage that is invisible in a diff and survives review.
    #
    # The control-character check exists because it happened: a scripted edit used a regex
    # replacement containing \b, which in a replacement string is a BACKSPACE escape rather
    # than a word boundary. Two 0x08 bytes were written into a live source file, turning
    # '(?i)\blab\b' into '(?i)<BS>lab<BS>' - a regex that silently matches nothing. It looked
    # correct in every editor and in git diff, and was caught only by chance.
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:sourceFiles = @(
        Get-ChildItem -Path (Join-Path $script:repoRoot 'source') -Recurse -File -Include '*.ps1', '*.psd1', '*.psm1', '*.ps1xml'
    )
    . (Join-Path $script:repoRoot 'scripts/private/Test-GraphKitPackagePrivacy.ps1')
}

Describe 'GraphKit.Auth authored project-source privacy' {

    It 'passes the reusable strict source privacy scan for every authored project file' {
        $authSourceRoot = Join-Path $script:repoRoot 'src/GraphKit.Auth'
        $authoredExtensions = @('.cs', '.csproj', '.props', '.sln', '.json')
        $expectedSourceFiles = @(
            Get-ChildItem -LiteralPath $authSourceRoot -Recurse -File -Force |
                Where-Object {
                    $_.Extension -iin $authoredExtensions -and
                    $_.FullName -notmatch '[\\/](?:bin|obj)[\\/]'
                }
        )
        $result = Test-GraphKitAuthSourcePrivacy `
            -SourceRoot $authSourceRoot `
            -ModuleGuid ([guid] (Import-PowerShellDataFile (Join-Path $script:repoRoot 'source/GraphKit.psd1')).GUID)

        $result.Passed | Should -BeTrue
        $expectedSourceFiles.Count | Should -BeGreaterThan 0
        $result.SourceFilesScanned | Should -Be $expectedSourceFiles.Count
        @($result.Findings).Count | Should -Be 0
    }

    It 'fails closed for invalid project-metadata encoding or an unapproved identifier' {
        $fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('graphkit-auth-source-privacy-' + [guid]::NewGuid().ToString('N'))
        try {
            New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
            [System.IO.File]::WriteAllText((Join-Path $fixtureRoot 'Valid.cs'), 'internal class Valid {}')
            [System.IO.File]::WriteAllBytes(
                (Join-Path $fixtureRoot 'Invalid.props'),
                [byte[]] @(0x3c, 0x50, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0xc3, 0x28)
            )

            {
                Test-GraphKitAuthSourcePrivacy -SourceRoot $fixtureRoot -ModuleGuid ([guid]::Empty)
            } | Should -Throw '*strict UTF-8*'

            [System.IO.File]::WriteAllText(
                (Join-Path $fixtureRoot 'Invalid.props'),
                '<Project><PropertyGroup><TenantId>01234567-89ab-4cde-8f01-23456789abcd</TenantId></PropertyGroup></Project>'
            )
            $result = Test-GraphKitAuthSourcePrivacy -SourceRoot $fixtureRoot -ModuleGuid ([guid]::Empty)
            $result.Passed | Should -BeFalse
            @($result.Findings).Category | Should -Contain 'GUID that is not a well-known or package id'
        }
        finally {
            Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'never treats an RFC-versioned repeated-segment GUID as a placeholder' {
        $allowedGuids = Get-GraphKitPackagePrivacyAllowedGuidSet -ModuleGuid ([guid]::Empty)

        foreach ($version in @('1', '2', '3', '4', '5', '6', '7', '8')) {
            foreach ($variant in @('8', '9', 'a', 'b')) {
                $candidate = "11111111-2222-$version$version$version$version-$variant$variant$variant$variant-555555555555"
                Test-GraphKitPackagePrivacyPlaceholderGuid -Value $candidate | Should -BeFalse
                $findings = [System.Collections.Generic.List[object]]::new()
                $findingKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
                Test-GraphKitPackagePrivacyText `
                    -Text $candidate `
                    -EntryName 'fixture.txt' `
                    -Encoding 'strict-utf8' `
                    -AllowedGuids $allowedGuids `
                    -Findings $findings `
                    -FindingKeys $findingKeys
                @($findings).Count | Should -Be 1
                $findings[0].Category |
                    Should -BeExactly 'GUID that is not a well-known or package id'
            }
        }

        $placeholder = '11111111-2222-4444-4444-555555555555'
        Test-GraphKitPackagePrivacyPlaceholderGuid `
            -Value $placeholder |
            Should -BeTrue
        $placeholderFindings = [System.Collections.Generic.List[object]]::new()
        $placeholderFindingKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        Test-GraphKitPackagePrivacyText `
            -Text $placeholder `
            -EntryName 'fixture.txt' `
            -Encoding 'strict-utf8' `
            -AllowedGuids $allowedGuids `
            -Findings $placeholderFindings `
            -FindingKeys $placeholderFindingKeys
        @($placeholderFindings).Count | Should -Be 0
    }

    It 'detects a hashed protected token embedded in a longer hyphenated identifier' {
        $realDigest = (Get-Command -Name Get-GraphKitPackagePrivacyDigest).ScriptBlock
        Mock Get-GraphKitPackagePrivacyDigest {
            if ($Value -ceq 'synthetic-protected-token') {
                return '5cad5cdbf022740cbfc976f9836ac89d00000000000000000000000000000000'
            }
            return (& $realDigest -Value $Value)
        }

        $allowedGuids = Get-GraphKitPackagePrivacyAllowedGuidSet -ModuleGuid ([guid]::Empty)
        $findings = [System.Collections.Generic.List[object]]::new()
        $findingKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

        Test-GraphKitPackagePrivacyText `
            -Text 'prefix-synthetic-protected-token-suffix' `
            -EntryName 'fixture.txt' `
            -Encoding 'strict-utf8' `
            -AllowedGuids $allowedGuids `
            -Findings $findings `
            -FindingKeys $findingKeys

        @($findings).Count | Should -Be 1
        $findings[0].Category | Should -BeExactly 'internal identifier - customer name (A)'

        $overBoundFindings = [System.Collections.Generic.List[object]]::new()
        $overBoundFindingKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        Test-GraphKitPackagePrivacyText `
            -Text ((1..33 | ForEach-Object { "segment$_" }) -join '-') `
            -EntryName 'fixture.txt' `
            -Encoding 'strict-utf8' `
            -AllowedGuids $allowedGuids `
            -Findings $overBoundFindings `
            -FindingKeys $overBoundFindingKeys

        @($overBoundFindings).Count | Should -Be 1
        $overBoundFindings[0].Category |
            Should -BeExactly 'hyphenated identifier exceeds bounded privacy scan'
    }

    It 'detects an unapproved wrapped GUID and permits only digest-approved vendor metadata' {
        $allowedGuids = Get-GraphKitPackagePrivacyAllowedGuidSet -ModuleGuid ([guid]::Empty)
        $findings = [System.Collections.Generic.List[object]]::new()
        $findingKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

        Test-GraphKitPackagePrivacyText `
            -Text 'prefixx87f7ad68-c47e-48b4-a248-49602bc19e84ysuffix' `
            -EntryName 'fixture.txt' `
            -Encoding 'strict-utf8' `
            -AllowedGuids $allowedGuids `
            -Findings $findings `
            -FindingKeys $findingKeys

        @($findings).Count | Should -Be 1
        $findings[0].Category | Should -BeExactly 'GUID that is not a well-known or package id'

        $realDigest = (Get-Command -Name Get-GraphKitPackagePrivacyDigest).ScriptBlock
        Mock Get-GraphKitPackagePrivacyDigest {
            if ($Value -ceq '87f7ad68-c47e-48b4-a248-49602bc19e84') {
                return '391ab33fdbbec5d86574ef81ce268caffeccdc6ea36e7940358e4ded01294842'
            }
            return (& $realDigest -Value $Value)
        }
        $vendorFindings = [System.Collections.Generic.List[object]]::new()
        $vendorFindingKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

        Test-GraphKitPackagePrivacyText `
            -Text 'prefixx87f7ad68-c47e-48b4-a248-49602bc19e84ysuffix' `
            -EntryName 'Assemblies/GraphKit.Auth/Microsoft.Identity.Client.dll' `
            -Encoding 'binary-utf16le' `
            -AllowedGuids $allowedGuids `
            -Findings $vendorFindings `
            -FindingKeys $vendorFindingKeys

        @($vendorFindings).Count | Should -Be 0

        $sourceFindings = [System.Collections.Generic.List[object]]::new()
        $sourceFindingKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        Test-GraphKitPackagePrivacyText `
            -Text 'prefixx87f7ad68-c47e-48b4-a248-49602bc19e84ysuffix' `
            -EntryName 'Assemblies/GraphKit.Auth/Microsoft.Identity.Client.dll' `
            -Encoding 'strict-utf8' `
            -AllowedGuids $allowedGuids `
            -Findings $sourceFindings `
            -FindingKeys $sourceFindingKeys

        @($sourceFindings).Count | Should -Be 1
        $sourceFindings[0].Category |
            Should -BeExactly 'GUID that is not a well-known or package id'

        $wrongEntryFindings = [System.Collections.Generic.List[object]]::new()
        $wrongEntryFindingKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        Test-GraphKitPackagePrivacyText `
            -Text 'prefixx87f7ad68-c47e-48b4-a248-49602bc19e84ysuffix' `
            -EntryName 'Assemblies/GraphKit.Auth/Unexpected.dll' `
            -Encoding 'binary-utf16le' `
            -AllowedGuids $allowedGuids `
            -Findings $wrongEntryFindings `
            -FindingKeys $wrongEntryFindingKeys

        @($wrongEntryFindings).Count | Should -Be 1
        $wrongEntryFindings[0].Category |
            Should -BeExactly 'GUID that is not a well-known or package id'

        $wrongGuidFindings = [System.Collections.Generic.List[object]]::new()
        $wrongGuidFindingKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        Test-GraphKitPackagePrivacyText `
            -Text 'prefixx89abcdef-0123-4abc-8def-0123456789abysuffix' `
            -EntryName 'Assemblies/GraphKit.Auth/Microsoft.Identity.Client.dll' `
            -Encoding 'binary-utf16le' `
            -AllowedGuids $allowedGuids `
            -Findings $wrongGuidFindings `
            -FindingKeys $wrongGuidFindingKeys

        @($wrongGuidFindings).Count | Should -Be 1
        $wrongGuidFindings[0].Category |
            Should -BeExactly 'GUID that is not a well-known or package id'
    }

    It 'fails closed when protected-token candidate generation reaches its fixed bound' {
        $runs = @(
            foreach ($runIndex in 0..15) {
                (@(0..31 | ForEach-Object { "r${runIndex}s$_" }) -join '-')
            }
        )
        $allowedGuids = Get-GraphKitPackagePrivacyAllowedGuidSet -ModuleGuid ([guid]::Empty)
        $findings = [System.Collections.Generic.List[object]]::new()
        $findingKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

        Test-GraphKitPackagePrivacyText `
            -Text ($runs -join ' ') `
            -EntryName 'fixture.txt' `
            -Encoding 'strict-utf8' `
            -AllowedGuids $allowedGuids `
            -Findings $findings `
            -FindingKeys $findingKeys

        @($findings).Count | Should -Be 1
        $findings[0].Category |
            Should -BeExactly 'protected-token candidate limit exceeded'
        $findings[0].EvidenceSha256 |
            Should -BeExactly (Get-GraphKitPackagePrivacyDigest -Value '8192')
    }
}

Describe 'Source hygiene' {

    It 'ships source files to check' {
        $script:sourceFiles.Count | Should -BeGreaterThan 0
    }

    It 'contains no control characters outside tab, CR and LF' {
        $offenders = foreach ($file in $script:sourceFiles) {
            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
            $bad = @($bytes | Where-Object { $_ -lt 0x20 -and $_ -notin 0x09, 0x0A, 0x0D })
            if ($bad.Count -gt 0) {
                "{0}: {1} control byte(s), first is 0x{2:X2}" -f $file.Name, $bad.Count, $bad[0]
            }
        }

        # -Because carries the diagnosis, since the failure is otherwise baffling to read.
        $offenders | Should -BeNullOrEmpty -Because 'a control byte in source is invisible in a diff and silently breaks the construct containing it'
    }

    It 'is valid UTF-8 with no replacement characters' {
        # A mangled encoding shows up as U+FFFD and corrupts whatever string contained it.
        $offenders = foreach ($file in $script:sourceFiles) {
            $text = [System.IO.File]::ReadAllText($file.FullName)
            if ($text.Contains([char] 0xFFFD)) { $file.Name }
        }
        $offenders | Should -BeNullOrEmpty
    }

    It 'has no source file that fails to parse' {
        # A file that does not parse cannot be caught by any behavioural test, because the
        # module never loads far enough to run one.
        $offenders = foreach ($file in ($script:sourceFiles | Where-Object Extension -in '.ps1', '.psm1')) {
            $errors = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref] $null, [ref] $errors)
            if ($errors -and $errors.Count -gt 0) {
                "{0}: {1}" -f $file.Name, $errors[0].Message
            }
        }
        $offenders | Should -BeNullOrEmpty
    }

    It 'carries no internal tenant, customer, or project identifiers' {
        # The module is published publicly. Internal names are meaningless to a consumer and
        # advertise private infrastructure, and a tenant id cannot be taken back once shipped.
        #
        # Customer names are matched by HASH, not by literal. This file is in a public
        # repository, so a regex naming a customer would publish the very name it exists to
        # keep out - the detector becomes the disclosure. Git history was rewritten
        # on 2026-08-16 to remove two customer identifiers, and restoring them here in plaintext
        # would have made that rewrite pointless.
        #
        # SHA-256 of the lowercased token, first 32 hex chars. To add a name: hash it the same
        # way and add the digest with a NON-identifying label. Never write the name itself.
        $secretTokenHashes = @{
            '5cad5cdbf022740cbfc976f9836ac89d' = 'customer name (A)'
            'e03427b1afcd1e84a97ed1f2241466cb' = 'internal workspace tenant'
            '9a08498936078c81ec926fedbce5e7c9' = 'customer name (A, short form)'
            '6ca05670c4afd49e806f7cddbab83b00' = 'lab tenant id'
        }

        # Project names that are NOT customer-identifying stay as literals - they are Adam's own
        # repositories, and hiding them would cost readability for no privacy gain.
        $patterns = @{
            'internal project name' = '(?i)\bivy24\b|\bIntuneHealthAutomation\b'
            'local user path'       = '/Users/[A-Za-z0-9._-]+|/home/[A-Za-z0-9._-]+|C:\\Users\\[A-Za-z0-9._-]+'
        }

        function Get-TokenDigest {
            param([string] $Token)
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($Token.ToLowerInvariant())
            return [System.BitConverter]::ToString(
                [System.Security.Cryptography.SHA256]::HashData($bytes)
            ).Replace('-', '').ToLowerInvariant().Substring(0, 32)
        }

        $offenders = foreach ($file in $script:sourceFiles) {
            $text = [System.IO.File]::ReadAllText($file.FullName)

            foreach ($label in $patterns.Keys) {
                $match = [regex]::Match($text, $patterns[$label])
                if ($match.Success) { "{0}: {1} ({2})" -f $file.Name, $label, $match.Value }
            }

            # Tokenize on word and GUID boundaries so a name is caught wherever it appears -
            # in a string, a path segment, a comment - without the name being written here.
            foreach ($token in [regex]::Matches($text, '[A-Za-z0-9][A-Za-z0-9-]{3,}')) {
                $digest = Get-TokenDigest -Token $token.Value
                if ($secretTokenHashes.ContainsKey($digest)) {
                    # Report the LABEL and the file, never the matched value - printing it would
                    # leak the name into CI logs, which are public on a public repository.
                    "{0}: internal identifier - {1}" -f $file.Name, $secretTokenHashes[$digest]
                }
            }
        }
        $offenders | Should -BeNullOrEmpty
    }
}
