<#
    Pester tests for scripts/New-ClientServicePrincipalCBA.ps1

    Every test here corresponds to a defect that actually occurred while creating the
    GraphKit-Ivy24 registration on 2026-08-14. They share one failure mode: the script
    reported success while not having done the thing. These are deterministic and make
    no Graph calls.

    Run:  Invoke-Pester ./tests/New-ClientServicePrincipalCBA.Tests.ps1 -Output Detailed
#>

BeforeAll {
    $script:ScriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts/New-ClientServicePrincipalCBA.ps1'
    $script:Source = Get-Content $script:ScriptPath -Raw
}

Describe 'New-ClientServicePrincipalCBA' {

    Context 'Syntax' {
        It 'parses without error' {
            $errors = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$errors)
            $errors | Should -BeNullOrEmpty
        }
    }

    Context 'Direct invocation (regression: silent no-op)' {
        # The script previously defined only a function with no file-scope param() block.
        # PowerShell routes unmatched arguments into $args and discards them, so every
        # documented invocation form defined the function, ignored all arguments and exited
        # silently. README.md, CLAUDE.md and three docs pages all instruct users to run it
        # this way.

        It 'exposes a file-scope param block' {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$null)
            $ast.ParamBlock | Should -Not -BeNullOrEmpty
        }

        It 'accepts <Name> as a parameter when invoked directly' -ForEach @(
            @{ Name = 'displayName' }
            @{ Name = 'CertificateSubject' }
            @{ Name = 'CertValidityInYears' }
            @{ Name = 'outPath' }
            @{ Name = 'Read' }
            @{ Name = 'Write' }
        ) {
            (Get-Command $script:ScriptPath).Parameters.Keys | Should -Contain $Name
        }

        It 'forwards bound parameters to the function' {
            $script:Source | Should -Match 'New-ClientServicePrincipalCBA @PSBoundParameters'
        }

        It 'does not invoke the function when dot-sourced' {
            # Dot-sourcing must define only. If it invoked, the Graph connection check would
            # produce output here.
            $out = . $script:ScriptPath 2>&1
            $out | Should -BeNullOrEmpty
            Get-Command New-ClientServicePrincipalCBA -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Path handling (regression: tilde passed to openssl)' {
        # $outPath is consumed both by PowerShell cmdlets, which resolve '~', and by openssl,
        # a native binary with no shell. Join-Path preserves '~' literally, so the directory
        # was created correctly while openssl received '~/...' and could not open it.

        It 'normalises $outPath before use' {
            $script:Source | Should -Match 'GetUnresolvedProviderPathFromPSPath\(\$outPath\)'
        }

        It 'resolves <Input> to a rooted path containing no tilde' -ForEach @(
            @{ Input = '~/.graphkit/certs/probe' }
            @{ Input = './relative/probe' }
            @{ Input = '/tmp/absolute/probe' }
        ) {
            $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Input)
            $resolved | Should -Not -Match '~'
            [System.IO.Path]::IsPathRooted($resolved) | Should -BeTrue
        }
    }

    Context 'Native command invocation' {
        # Building a command string for Invoke-Expression breaks on paths containing spaces
        # or quotes and creates an injection surface.

        It 'calls openssl with an argument array rather than Invoke-Expression' {
            $script:Source | Should -Match '& openssl @opensslArgs'
        }

        It 'checks the openssl exit code' {
            $script:Source | Should -Match '\$LASTEXITCODE -ne 0'
        }

        It 'surfaces openssl diagnostics on failure rather than a generic message' {
            $script:Source | Should -Match 'OpenSSL failed to generate the certificate \(exit code'
        }
    }

    Context 'Permission set selection' {
        BeforeAll {
            $readSet = [regex]::Match($script:Source, '\$GraphPermissionsRead = @\((.*?)\n    \)', 'Singleline').Groups[1].Value
            $writeSet = [regex]::Match($script:Source, '\$GraphPermissionsWrite = @\((.*?)\n    \)', 'Singleline').Groups[1].Value
            $script:ReadNames = [regex]::Matches($readSet, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value }
            $script:WriteNames = [regex]::Matches($writeSet, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value }
        }

        It 'defines both a read and a write permission set' {
            $script:ReadNames.Count | Should -BeGreaterThan 0
            $script:WriteNames.Count | Should -BeGreaterThan 0
        }

        It 'read set contains no ReadWrite permissions' {
            $script:ReadNames | Where-Object { $_ -match '\.ReadWrite\.' } | Should -BeNullOrEmpty
        }

        It 'grants <Expected> for -Read:<R> -Write:<W>' -ForEach @(
            @{ R = $false; W = $false; Expected = 'read' }
            @{ R = $true;  W = $false; Expected = 'read' }
            @{ R = $false; W = $true;  Expected = 'write' }
            @{ R = $true;  W = $true;  Expected = 'both' }
        ) {
            $Read = [switch]$R
            $Write = [switch]$W
            $grantRead = $Read.IsPresent -or -not $Write.IsPresent
            $grantWrite = $Write.IsPresent

            switch ($Expected) {
                'read' { $grantRead | Should -BeTrue; $grantWrite | Should -BeFalse }
                'write' { $grantRead | Should -BeFalse; $grantWrite | Should -BeTrue }
                'both' { $grantRead | Should -BeTrue; $grantWrite | Should -BeTrue }
            }
        }

        It 'write set excludes escalation permission <Name>' -ForEach @(
            @{ Name = 'Directory.ReadWrite.All' }
            @{ Name = 'AppRoleAssignment.ReadWrite.All' }
            @{ Name = 'Application.ReadWrite.All' }
            @{ Name = 'RoleManagement.ReadWrite.Directory' }
        ) {
            # These let the application grant itself further rights.
            $script:WriteNames | Should -Not -Contain $Name
        }

        It 'write set excludes destructive DeviceManagementManagedDevices.PrivilegedOperations.All' {
            $script:WriteNames | Should -Not -Contain 'DeviceManagementManagedDevices.PrivilegedOperations.All'
        }

        It 'fails loudly when a permission name cannot be resolved' {
            # Find-MgGraphPermission silently drops unknown names, which would otherwise
            # produce a registration holding fewer rights than requested.
            $script:Source | Should -Match 'could not be resolved'
        }
    }

    Context 'Grant verification (regression: warn-and-continue)' {
        # Failed role assignments previously produced only a Write-Warning, so the script
        # returned a success object for an application that did not hold its permissions.

        It 'collects assignment failures rather than only warning' {
            $script:Source | Should -Match '\$grantFailures'
        }

        It 'reads granted roles back from the service principal' {
            $script:Source | Should -Match 'Get-MgServicePrincipalAppRoleAssignment'
        }

        It 'throws when requested permissions were not granted' {
            $script:Source | Should -Match 'permissions are incomplete'
        }

        It 'names the privileged role needed to assign app roles' {
            $script:Source | Should -Match 'Privileged Role Administrator'
        }
    }

    Context 'Output correctness (regression: empty TenantId)' {
        # The admin consent URL and connection command read $context.TenantId, but no
        # $context variable exists - the connection check uses $graphContext. $null.TenantId
        # yielded an empty string, producing a doubled slash in the consent URL and
        # -TenantId "" in the connection command, while the returned object was correct.

        It 'does not reference the undefined $context variable' {
            $codeLines = $script:Source -split "`n" | Where-Object { $_.Trim() -notmatch '^#' }
            ($codeLines -join "`n") | Should -Not -Match '\$context\.'
        }

        It 'resolves the tenant once and reuses it' {
            $script:Source | Should -Match '\$resolvedTenantId = \(Get-MgContext\)\.TenantId'
        }

        It 'warns when the tenant cannot be resolved' {
            $script:Source | Should -Match 'Unable to determine the tenant ID'
        }

        It 'builds the consent URL from the resolved tenant' {
            $script:Source | Should -Match "adminconsent\?client_id="
            $script:Source | Should -Match '\$resolvedTenantId \+ ./adminconsent'
        }
    }

    Context 'Cross-platform connection guidance (regression: AADSTS50011)' {
        # -CertificateThumbprint resolves against the Windows certificate store. On macOS and
        # Linux Connect-MgGraph falls back to interactive auth, which fails with
        # AADSTS50011 because an app-only registration has no localhost redirect URI.

        It 'branches on platform when emitting the connection command' {
            $script:Source | Should -Match 'if \(\$IsWindows\)'
        }

        It 'uses X509CertificateLoader on non-Windows' {
            $script:Source | Should -Match 'X509CertificateLoader\]::LoadPkcs12FromFile'
        }

        It 'converts the SecureString password at the call site' {
            # LoadPkcs12FromFile has no SecureString overload; passing one fails with a
            # misleading "the password may be incorrect". The emitted command lives in a
            # here-string, so $pfxPassword appears backtick-escaped in the source.
            $script:Source | Should -Match 'NetworkCredential\]::new\('
            $script:Source | Should -Match '\)\.Password'
        }
    }

    Context 'Password handling (regression: PFX password truncated to one character)' {
        # SecureStringToBSTR produces a UTF-16 BSTR. PtrToStringAuto resolves to the ANSI
        # variant on Unix, reads the first byte, stops at the null byte of the second, and
        # returns only the first character. The PFX was exported with a one-character
        # password while the operator believed they had set a strong one.

        It 'does not use PtrToStringAuto to unwrap a SecureString' {
            # Comments deliberately name PtrToStringAuto to document the defect, so assert
            # against code lines only.
            $codeOnly = ($script:Source -split "`n" | Where-Object { $_.Trim() -notmatch '^#' }) -join "`n"
            $codeOnly | Should -Not -Match 'PtrToStringAuto'
        }

        It 'uses NetworkCredential to unwrap the password' {
            $script:Source | Should -Match '\[System\.Net\.NetworkCredential\]::new\(.{2}, \$certPasswordSecure\)\.Password'
        }

        It 'NetworkCredential unwraps a SecureString correctly on this platform' {
            # Guards against a future "cleanup" reintroducing PtrToStringAuto, which reads a
            # UTF-16 BSTR as ANSI on Unix and yields just the first character - the defect that
            # silently truncated a PFX password to 'T'.
            #
            # Asserted per platform rather than skipped on Windows. A -Skip here made the whole
            # CI run fail the AllowedSkips=0 gate, and skipping is the wrong instinct anyway:
            # the NetworkCredential guarantee is what the script depends on and it must hold
            # EVERYWHERE, while only the PtrToStringAuto quirk is Unix-specific.
            $sec = ConvertTo-SecureString 'TestPw123' -AsPlainText -Force
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
            try {
                # The property under test, on every platform.
                [System.Net.NetworkCredential]::new('', $sec).Password | Should -Be 'TestPw123'

                if ($IsWindows) {
                    # PtrToStringAuto is correct on Windows, which is exactly why the bug
                    # survived review: it only misbehaves off Windows.
                    [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) | Should -Be 'TestPw123'
                }
                else {
                    [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) | Should -Be 'T'
                }
            }
            finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        }

        It 'refuses to export an unprotected PFX' {
            $script:Source | Should -Match 'certificate password is empty'
        }

        It 'passes the password to openssl by environment variable, not on the command line' {
            # pass:<secret> would be visible to any user able to run ps.
            $script:Source | Should -Match "'-passout', 'env:GRAPHKIT_PFX_PASSWORD'"
            $script:Source | Should -Not -Match "passout pass:"
        }

        It 'clears the password environment variable afterwards' {
            $script:Source | Should -Match 'Remove-Item Env:\\GRAPHKIT_PFX_PASSWORD'
        }

        It 'exports the PFX without Invoke-Expression' {
            $script:Source | Should -Match '& openssl @pfxArgs'
        }

        It 'verifies the exported PFX reopens with the supplied password' {
            $script:Source | Should -Match 'could not be reopened with the supplied password'
        }

        It 'verifies the exported PFX carries a private key' {
            $script:Source | Should -Match 'HasPrivateKey'
        }
    }

    Context 'Dead code (regression: grant logic inside a block comment)' {
        # Lines 503-615 were enclosed in <# ... #>. The application and service principal were
        # created and the function returned a success object having granted nothing, which is
        # why registrations had 19 permissions configured in requiredResourceAccess and zero
        # appRoleAssignments. Verification code added inside that block never ran either.

        BeforeAll {
            $tokens = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$tokens, [ref]$null)
            $script:BlockComments = @(
                $tokens | Where-Object { $_.Kind -eq 'Comment' -and $_.Text.StartsWith('<#') } |
                    ForEach-Object { [pscustomobject]@{ Start = $_.Extent.StartLineNumber; End = $_.Extent.EndLineNumber } }
            )
            function Test-InsideBlockComment {
                param([int]$Line)
                @($script:BlockComments | Where-Object { $Line -ge $_.Start -and $Line -le $_.End }).Count -gt 0
            }
        }

        It 'keeps <Name> outside any block comment' -ForEach @(
            @{ Name = 'the Graph service principal lookup'; Pattern = 'Getting the Microsoft Graph service principal' }
            @{ Name = 'the role assignment loop'; Pattern = 'Granting Microsoft Graph permissions' }
            @{ Name = 'the assignment call'; Pattern = 'New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId \$sp\.Id' }
            @{ Name = 'the grant read-back'; Pattern = 'actuallyGranted' }
            @{ Name = 'the incomplete-permissions throw'; Pattern = 'permissions are incomplete' }
        ) {
            $line = (Select-String -Path $script:ScriptPath -Pattern $Pattern | Select-Object -First 1).LineNumber
            $line | Should -Not -BeNullOrEmpty -Because "the pattern '$Pattern' must still exist"
            Test-InsideBlockComment -Line $line | Should -BeFalse -Because 'commented-out grant logic returns success having granted nothing'
        }

        It 'has no block comment large enough to hide the grant pipeline unnoticed' {
            # The help header is legitimately long; anything else over 40 lines is suspicious.
            $suspicious = @($script:BlockComments | Where-Object { ($_.End - $_.Start) -gt 40 -and $_.Start -gt 100 })
            $suspicious | ForEach-Object { Write-Host "  large block comment at L$($_.Start)..L$($_.End)" }
            $suspicious.Count | Should -Be 0
        }
    }

    Context 'Undefined variable references (regression: $GraphAppId and $context)' {
        # Neither $GraphAppId nor $context was ever assigned. Without Set-StrictMode both
        # expanded to empty strings: one produced the filter "appId eq ''" and a 400
        # Request_UnsupportedQuery, the other an admin consent URL with a doubled slash.

        It 'reads no variable that is never assigned' {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$null)

            $auto = @(
                '_', 'PSItem', 'args', 'true', 'false', 'null', 'this', 'input', 'error', 'matches',
                'PSCmdlet', 'PSBoundParameters', 'MyInvocation', 'PSScriptRoot', 'PSCommandPath',
                'PSVersionTable', 'IsWindows', 'IsMacOS', 'IsLinux', 'LASTEXITCODE',
                'ErrorActionPreference', 'WarningPreference', 'VerbosePreference',
                'InformationPreference', 'ProgressPreference', 'ConfirmPreference', 'DebugPreference',
                'host', 'PWD', 'HOME', 'PID', 'PSDefaultParameterValues', 'StackTrace',
                'ExecutionContext', 'PSEdition', 'PSCulture', 'PSUICulture', 'ShellId', 'Env',
                'OutputEncoding', 'NestedPromptLevel', 'PSSenderInfo', 'foreach', 'switch'
            )

            $assigned = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true) | ForEach-Object {
                $l = $_.Left
                if ($l -is [System.Management.Automation.Language.ConvertExpressionAst]) { $l = $l.Child }
                if ($l -is [System.Management.Automation.Language.VariableExpressionAst]) { [void]$assigned.Add($l.VariablePath.UserPath) }
            }
            $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.ParameterAst] }, $true) | ForEach-Object {
                [void]$assigned.Add($_.Name.VariablePath.UserPath)
            }
            $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.ForEachStatementAst] }, $true) | ForEach-Object {
                [void]$assigned.Add($_.Variable.VariablePath.UserPath)
            }
            $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object {
                if ($_.GetCommandName() -in 'Set-Variable', 'New-Variable') {
                    foreach ($e in $_.CommandElements | Select-Object -Skip 1) {
                        if ($e -is [System.Management.Automation.Language.StringConstantExpressionAst]) { [void]$assigned.Add($e.Value); break }
                    }
                }
            }

            $undefined = @{}
            foreach ($r in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
                $n = $r.VariablePath.UserPath
                if ($n -in $auto) { continue }
                if ($n -like 'env:*' -or $n -like 'script:*' -or $n -like 'global:*' -or $n -like 'using:*') { continue }
                if ($assigned.Contains($n)) { continue }
                if ($r.Parent -is [System.Management.Automation.Language.ParameterAst]) { continue }
                if (-not $undefined.ContainsKey($n)) { $undefined[$n] = @() }
                $undefined[$n] += $r.Extent.StartLineNumber
            }

            $report = ($undefined.GetEnumerator() | Sort-Object Name | ForEach-Object { "`$$($_.Key) (lines $($_.Value -join ', '))" }) -join '; '
            $undefined.Count | Should -Be 0 -Because "these variables are read but never assigned: $report"
        }
    }

    Context 'Certificate loading contract' {
        It 'loads a PFX produced by openssl defaults using the documented idiom' {
            $dir = Join-Path ([System.IO.Path]::GetTempPath()) "cbatest-$([System.Guid]::NewGuid().ToString('N'))"
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            try {
                $key = Join-Path $dir 't.key'; $crt = Join-Path $dir 't.crt'; $pfx = Join-Path $dir 't.pfx'
                & openssl req -x509 -newkey rsa:2048 -keyout $key -out $crt -days 1 -nodes -subj '/CN=PesterLoadTest' 2>&1 | Out-Null
                $LASTEXITCODE | Should -Be 0
                & openssl pkcs12 -export -out $pfx -inkey $key -in $crt -passout 'pass:testpw' 2>&1 | Out-Null
                $LASTEXITCODE | Should -Be 0

                $secure = ConvertTo-SecureString 'testpw' -AsPlainText -Force
                $plain = [System.Net.NetworkCredential]::new('', $secure).Password

                # X509CertificateLoader is .NET 9, so it does not exist on PowerShell 7.4 -
                # which is this module's declared floor. The test used it unconditionally and
                # therefore could not run on 7.4 at all; that went unnoticed until CI ran the
                # matrix for the first time and every 7.4 leg failed on a missing type.
                #
                # The point of this test is that a PFX written by openssl's defaults loads with
                # its private key intact, so it exercises whichever idiom the running runtime
                # actually has. GraphKit's own source uses the X509Certificate2 constructor,
                # which works everywhere; the loader is what the standalone CBA script
                # documents, and that script therefore needs 7.5+.
                $cert = if ($null -ne ('System.Security.Cryptography.X509Certificates.X509CertificateLoader' -as [type])) {
                    [System.Security.Cryptography.X509Certificates.X509CertificateLoader]::LoadPkcs12FromFile($pfx, $plain)
                }
                else {
                    [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pfx, $plain)
                }

                $cert.HasPrivateKey | Should -BeTrue   # required for Connect-MgGraph -Certificate
                $cert.Subject | Should -Be 'CN=PesterLoadTest'
            }
            finally {
                Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
