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
            'local user path'       = '/Users/[A-Za-z0-9._-]+|C:\\Users\\[A-Za-z0-9._-]+'
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
