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
        $patterns = @{
            'internal tenant/project name' = '(?i)\bivy24\b|\bIntuneHealthAutomation\b|\bfabrikam\b|\bcontoso\b'
            'local user path'             = '/Users/[A-Za-z0-9._-]+|C:\\Users\\[A-Za-z0-9._-]+'
        }

        $offenders = foreach ($file in $script:sourceFiles) {
            $text = [System.IO.File]::ReadAllText($file.FullName)
            foreach ($label in $patterns.Keys) {
                $match = [regex]::Match($text, $patterns[$label])
                if ($match.Success) { "{0}: {1} ({2})" -f $file.Name, $label, $match.Value }
            }
        }
        $offenders | Should -BeNullOrEmpty
    }
}
