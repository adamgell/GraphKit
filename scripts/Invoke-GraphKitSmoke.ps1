<#
    .SYNOPSIS
        Protected Ivy24 smoke workflow: verify the package digest, read, mutate and revert a lab
        mobile app assignment against a real tenant, with cleanup guaranteed even on assertion failure.

    .DESCRIPTION
        Gate 1.8 (spec "Phases" row 1.8). A STANDALONE protected-environment runner — deliberately
        a script, not a module function, and never referenced by deterministic CI. It runs against a
        real Ivy24 tenant ONLY when invoked deliberately.

        Flow:
          1. Verify the package digest: locate the built .nupkg (or the installed GraphKit module)
             and assert its sha256 equals -PackageHash, aborting BEFORE any live call and naming both
             hashes on mismatch.
          2. Resolve the profile into an immutable context via Get-GraphContext.
          3. Live READ: Get-GraphObject -Type ManagedDevice -Operation List (assert Succeeded; any
             non-success fails with the envelope's Outcome/Certainty).
          4. Live MUTATION: capture the app's current assignments, apply a test assignment to a
             single lab group (-TestGroupId), and IMMEDIATELY revert to the captured prior state.
          5. CLEANUP GUARANTEED: the revert runs in a finally block, so an assertion failure mid-test
             still restores the prior assignment state.
          6. Emit a JSON summary (profile, digest verified, read outcome/device count, mutation
             applied+reverted, cleanup state, timestamps). The summary NEVER carries bearer tokens,
             secrets, or tenant ids; any GUID-shaped value is redacted to 'REDACTED'.

        -DryRun runs the same control flow with a stubbed transport (zero network) and still
        exercises the digest check and the cleanup ordering. The digest check is bypassable ONLY in
        -DryRun when no package exists, signalled by the sentinel hash 'dryrun'.

    .PARAMETER ProfileId
        The canonical profile identifier to resolve via Get-GraphContext. Defaults to 'ivy24'.

    .PARAMETER PackageHash
        The sha256 hex digest of the tested .nupkg. Mandatory for a live run. In -DryRun it may be
        omitted to use the sentinel hash 'dryrun' (accepted only when no package is locatable).

    .PARAMETER AppId
        The lab mobile app (object id) used for the mutation. Required for a live run.

    .PARAMETER TestGroupId
        The single lab group id the test assignment targets. Required for a live run.

    .PARAMETER TimeoutMinutes
        Maximum total elapsed time for the whole workflow. Defaults to 10.

    .PARAMETER DryRun
        Run the same control flow with an injected stub transport scriptblock; zero network. Still
        validates the digest check and the cleanup ordering.

    .PARAMETER TransportStub
        The stub transport scriptblock used when -DryRun is supplied. Invoked as
        & $TransportStub -Kind '<Kind>' -Payload <hashtable> and must return an envelope-shaped
        object (at least Outcome, Data, Certainty). When omitted, the committed dry-run stub
        (New-GraphKitSmokeDryRunTransport) is used.

    .EXAMPLE
        pwsh -NoProfile -File ./scripts/Invoke-GraphKitSmoke.ps1 -DryRun

        Dry-run against the committed stub: every step reports PASS or SKIP and the process exits 0.

    .EXAMPLE
        pwsh -NoProfile -File ./scripts/Invoke-GraphKitSmoke.ps1 `
            -PackageHash 0123... -AppId 11111111-... -TestGroupId 22222222-... -TimeoutMinutes 15

        Live protected run against the Ivy24 tenant (deliberate, never from CI).
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string] $ProfileId = 'ivy24',

    [Parameter()]
    [string] $PackageHash,

    [Parameter()]
    [guid] $AppId,

    [Parameter()]
    [guid] $TestGroupId,

    [Parameter()]
    [ValidateRange(1, 1440)]
    [int] $TimeoutMinutes = 10,

    [Parameter()]
    [switch] $DryRun,

    [Parameter()]
    [scriptblock] $TransportStub
)

# ---------------------------------------------------------------------------
# Pure helpers (unit-tested; no network, no vault, no module dependency).
# ---------------------------------------------------------------------------

<#
    Compares the computed package digest against the expected sha256. Throws an actionable error
    naming both hashes on mismatch. Pure: no filesystem or network access.
#>
function Test-GraphKitSmokeDigest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ExpectedHash,

        [Parameter(Mandatory)]
        [string] $ActualHash,

        [Parameter()]
        [string] $PackagePath = '<unknown package>'
    )

    if ([string]::IsNullOrWhiteSpace($ExpectedHash)) {
        throw 'The expected package digest is empty; a protected smoke run must name the tested sha256.'
    }

    if (-not [string]::Equals($ExpectedHash, $ActualHash, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ("Package digest mismatch for '{0}': expected sha256 '{1}' but computed sha256 '{2}'. Aborting before any live call." -f `
                $PackagePath, $ExpectedHash, $ActualHash)
    }

    return $true
}

<#
    Deep-recurses a value, replacing every GUID-shaped string (and [guid]) with 'REDACTED'. Used as
    defense-in-depth before the JSON summary is emitted so no tenant id / bearer / secret ever leaks.
#>
function Protect-GraphKitSmokeSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $InputObject
    )

    return ConvertTo-GraphKitSmokeRedacted -Value $InputObject
}

function ConvertTo-GraphKitSmokeRedacted {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [guid]) {
        return 'REDACTED'
    }

    if ($Value -is [string]) {
        return [regex]::Replace(
            $Value,
            '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            'REDACTED')
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($key in @($Value.Keys)) {
            $out[$key] = ConvertTo-GraphKitSmokeRedacted -Value $Value[$key]
        }
        return $out
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Value) {
            $list.Add((ConvertTo-GraphKitSmokeRedacted -Value $item))
        }
        return , $list.ToArray()
    }

    if ($Value -is [PSCustomObject]) {
        $copy = [PSCustomObject]@{}
        foreach ($prop in $Value.PSObject.Properties) {
            Add-Member -InputObject $copy -NotePropertyName $prop.Name `
                -NotePropertyValue (ConvertTo-GraphKitSmokeRedacted -Value $prop.Value) -Force
        }
        return $copy
    }

    return $Value
}

<#
    Computes a sha256 for a package artifact: the raw bytes of a .nupkg file, or (with -Directory) a
    deterministic fingerprint of a module directory (relative path + file bytes, in sorted order).
#>
function Get-GraphKitSmokePackageHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter()]
        [switch] $Directory
    )

    if (-not $Directory) {
        return (Get-FileHash -Path $Path -Algorithm SHA256).Hash
    }

    $files = @(Get-ChildItem -Path $Path -File -Recurse -ErrorAction Stop)
    if ($files.Count -eq 0) {
        throw "No files found under package directory '$Path'."
    }

    $root = $Path.TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    $files = $files | Sort-Object { $_.FullName.Substring($root.Length).TrimStart([System.IO.Path]::DirectorySeparatorChar) }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $parts = [System.Collections.Generic.List[byte]]::new()
        foreach ($file in $files) {
            $relative = $file.FullName.Substring($root.Length).TrimStart([System.IO.Path]::DirectorySeparatorChar).Replace('\', '/')
            $parts.AddRange([System.Text.Encoding]::UTF8.GetBytes($relative + "`0"))
            $parts.AddRange($sha.ComputeHash([System.IO.File]::ReadAllBytes($file.FullName)))
        }
        return ([System.BitConverter]::ToString($sha.ComputeHash($parts.ToArray())).Replace('-', ''))
    }
    finally {
        $sha.Dispose()
    }
}

<#
    Locates the tested package: the most recently built .nupkg under output/, else the installed
    GraphKit module. Returns @{ Path; Kind; Hash } or $null when no package exists. The loose build
    directory under output/module is deliberately NOT treated as a package (spec: gates test the
    installed package, never loose output/ files).
#>
function Find-GraphKitSmokePackage {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string] $RepoRoot = (Split-Path $PSScriptRoot -Parent)
    )

    $nupkg = Get-ChildItem -Path (Join-Path $RepoRoot 'output') -Filter '*.nupkg' -Recurse -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    if ($null -ne $nupkg) {
        return @{
            Path = $nupkg.FullName
            Kind = 'Nupkg'
            Hash = (Get-GraphKitSmokePackageHash -Path $nupkg.FullName)
        }
    }

    $installed = Get-Module -Name 'GraphKit' -ListAvailable -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending | Select-Object -First 1
    if ($null -ne $installed) {
        return @{
            Path = $installed.ModuleBase
            Kind = 'InstalledModule'
            Hash = (Get-GraphKitSmokePackageHash -Path $installed.ModuleBase -Directory)
        }
    }

    return $null
}

# ---------------------------------------------------------------------------
# Orchestration (transport-agnostic; unit-tested with a stub transport).
# ---------------------------------------------------------------------------

<#
    Runs the read -> capture -> mutate -> revert-in-finally sequence against an injected transport.
    The transport is invoked as `& $Transport -Kind '<Kind>' -Payload <hashtable>` and must return an
    envelope-shaped object with at least Outcome, Data and Certainty. Kinds:
        ManagedDeviceList -> envelope with Data = device rows
        AppAssignments    -> envelope with Data = the current assignment array
        Assign            -> envelope; Payload.Assignments = the assignment array to apply
        Revert            -> envelope; Payload.Assignments = the prior assignment array to restore

    A failed read or mutation assertion throws (after writing a FAIL line); the revert runs in a
    finally block so the prior state is restored even when an assertion throws. Step ordering is
    recorded in -Trace: 'read', 'capture', 'assign', then 'revert'/'revert-failed'/'cleanup-skip'.
#>
function Invoke-GraphKitSmokeFlow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        [guid] $AppId,

        [Parameter(Mandatory)]
        [guid] $TestGroupId,

        [Parameter(Mandatory)]
        [scriptblock] $Transport,

        [Parameter()]
        [datetime] $DeadlineUtc = ([datetime]::MaxValue),

        [Parameter()]
        [System.Collections.Generic.List[string]] $Trace
    )

    if ($null -eq $Trace) {
        $Trace = [System.Collections.Generic.List[string]]::new()
    }

    $startedUtc = [datetime]::UtcNow
    $applied = $false
    $attempted = $false
    $reverted = $false
    $readOutcome = $null
    $deviceCount = $null
    $priorAssignments = $null
    $cleanupState = 'None'

    try {
        if ([datetime]::UtcNow -gt $DeadlineUtc) { throw 'Smoke workflow deadline expired before the read step.' }

        # Step 3: live READ (assert Succeeded; any non-success fails with envelope detail).
        $readEnv = & $Transport -Kind 'ManagedDeviceList' -Payload @{ }
        $readOutcome = [string] $readEnv.Outcome
        if ($readOutcome -ne 'Succeeded') {
            $detail = 'Outcome={0}; Certainty={1}' -f $readEnv.Outcome, $readEnv.Certainty
            Write-Host ("FAIL  read ManagedDevice.List: {0}" -f $detail) -ForegroundColor Red
            throw ("Smoke READ assertion failed: {0}" -f $detail)
        }
        $deviceCount = @($readEnv.Data).Count
        $Trace.Add('read')
        Write-Host ("PASS  read ManagedDevice.List: {0} device(s)" -f $deviceCount) -ForegroundColor Green

        if ([datetime]::UtcNow -gt $DeadlineUtc) { throw 'Smoke workflow deadline expired before the capture step.' }

        # Step 4a: capture the app's current assignments.
        $captureEnv = & $Transport -Kind 'AppAssignments' -Payload @{ AppId = $AppId }
        if ([string] $captureEnv.Outcome -ne 'Succeeded') {
            $detail = 'Outcome={0}; Certainty={1}' -f $captureEnv.Outcome, $captureEnv.Certainty
            Write-Host ("FAIL  capture current app assignments: {0}" -f $detail) -ForegroundColor Red
            throw ("Smoke capture assertion failed: {0}" -f $detail)
        }
        $priorAssignments = $captureEnv.Data
        $Trace.Add('capture')
        Write-Host 'PASS  captured current app assignment state' -ForegroundColor Green

        if ([datetime]::UtcNow -gt $DeadlineUtc) { throw 'Smoke workflow deadline expired before the mutation step.' }

        # Step 4b: apply the test assignment (a single lab group id), then assert.
        $testAssignments = @(
            @{
                '@odata.type' = '#microsoft.graph.mobileAppAssignment'
                target         = @{
                    '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                    groupId       = [string] $TestGroupId
                }
            }
        )

        $assignEnv = & $Transport -Kind 'Assign' -Payload @{ AppId = $AppId; Assignments = $testAssignments }
        $attempted = $true
        $Trace.Add('assign')
        if ([string] $assignEnv.Outcome -ne 'Succeeded') {
            $mutationError = 'Outcome={0}; Certainty={1}' -f $assignEnv.Outcome, $assignEnv.Certainty
            Write-Host ("FAIL  apply test assignment: {0}" -f $mutationError) -ForegroundColor Red
            throw ("Smoke MUTATION assertion failed: {0}" -f $mutationError)
        }
        $applied = $true
        Write-Host 'PASS  applied test assignment to lab group' -ForegroundColor Green
    }
    finally {
        # Step 5: CLEANUP GUARANTEED — the revert runs even when an assertion above threw.
        if ($attempted) {
            $revertEnv = & $Transport -Kind 'Revert' -Payload @{ AppId = $AppId; Assignments = $priorAssignments }
            if ([string] $revertEnv.Outcome -eq 'Succeeded') {
                $reverted = $true
                $cleanupState = 'Reverted'
                $Trace.Add('revert')
                Write-Host 'PASS  reverted to prior assignment state' -ForegroundColor Green
            }
            else {
                $cleanupState = 'RevertFailed'
                $Trace.Add('revert-failed')
                Write-Host ("FAIL  revert to prior assignment state: Outcome={0}" -f $revertEnv.Outcome) -ForegroundColor Red
            }
        }
        else {
            $cleanupState = 'NothingToRevert'
            $Trace.Add('cleanup-skip')
            Write-Host 'SKIP  no assignment mutation was attempted; nothing to revert' -ForegroundColor Yellow
        }
    }

    return [ordered]@{
        Profile      = $Context.ProfileId
        ReadOutcome  = [ordered]@{ Outcome = $readOutcome; DeviceCount = $deviceCount }
        Mutation     = [ordered]@{ Applied = $applied; Reverted = $reverted }
        CleanupState = $cleanupState
        StartedUtc   = $startedUtc.ToString('o')
        CompletedUtc = [datetime]::UtcNow.ToString('o')
    }
}

# ---------------------------------------------------------------------------
# Transport builders.
# ---------------------------------------------------------------------------

<#
    The committed dry-run transport: returns scripted Succeeded envelopes for every smoke step with
    zero network. A substitute for a real transport in -DryRun when no -TransportStub is supplied.
#>
function New-GraphKitSmokeDryRunTransport {
    [CmdletBinding()]
    param()

    return {
        param(
            [Parameter(Mandatory)]
            [string] $Kind,

            [Parameter()]
            [hashtable] $Payload
        )

        switch ($Kind) {
            'ManagedDeviceList' { return [PSCustomObject]@{ Outcome = 'Succeeded'; Certainty = 'Known'; Data = @(@{ id = 'dryrun-device-1' }) } }
            'AppAssignments'    { return [PSCustomObject]@{ Outcome = 'Succeeded'; Certainty = 'Known'; Data = @() } }
            'Assign'            { return [PSCustomObject]@{ Outcome = 'Succeeded'; Certainty = 'Known'; Data = $null } }
            'Revert'            { return [PSCustomObject]@{ Outcome = 'Succeeded'; Certainty = 'Known'; Data = $null } }
            default             { throw "Unsupported smoke transport kind '$Kind'." }
        }
    }
}

<#
    Builds the LIVE transport that dispatches each smoke step through the GraphKit public surface.
    Only constructed in a deliberate (non -DryRun) run, after the module is imported.
#>
function New-GraphKitSmokeLiveTransport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        [guid] $AppId
    )

    return {
        param(
            [Parameter(Mandatory)]
            [string] $Kind,

            [Parameter()]
            [hashtable] $Payload
        )

        switch ($Kind) {
            'ManagedDeviceList' {
                return Get-GraphObject -Context $Context -Type ManagedDevice -Operation List -PassThruResult
            }
            'AppAssignments' {
                $uri = '{0}/v1.0/deviceAppManagement/mobileApps/{1}/assignments' -f `
                    $Context.GraphBaseUri.AbsoluteUri.TrimEnd('/'), [string] $Payload.AppId
                $env = Invoke-GraphOperation -Context $Context -Uri ([uri] $uri) -Method GET
                if ($env.Outcome -eq 'Succeeded' -and $env.Data -is [System.Collections.IDictionary] -and $env.Data.ContainsKey('value')) {
                    $env.Data = $env.Data['value']
                }
                return $env
            }
            'Assign' {
                return Invoke-GraphOperation -Context $Context -Type MobileApp -Operation Assign -Parameters @{
                    id   = [string] $Payload.AppId
                    Body = @{ mobileAppAssignments = @($Payload.Assignments) }
                }
            }
            'Revert' {
                return Invoke-GraphOperation -Context $Context -Type MobileApp -Operation Assign -Parameters @{
                    id   = [string] $Payload.AppId
                    Body = @{ mobileAppAssignments = @($Payload.Assignments) }
                }
            }
            default { throw "Unsupported smoke transport kind '$Kind'." }
        }
    }
}

# ---------------------------------------------------------------------------
# Main entry — runs only when executed as a script (not when dot-sourced by tests).
# ---------------------------------------------------------------------------

if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference = 'Stop'

    $startedUtc = [datetime]::UtcNow
    $trace = [System.Collections.Generic.List[string]]::new()
    $summary = [ordered]@{
        Profile             = $ProfileId
        DryRun              = [bool] $DryRun
        PackageHashVerified = $null
        StartedUtc          = $startedUtc.ToString('o')
    }
    $exitCode = 0

    # A [guid] parameter left unbound is $null (PowerShell does not default it to Empty); normalize
    # so the flow and the live-run guard below see a well-formed value.
    if ($null -eq $AppId) { $AppId = [guid]::Empty }
    if ($null -eq $TestGroupId) { $TestGroupId = [guid]::Empty }

    try {
        # 1. Package digest — abort BEFORE any live call on mismatch.
        if ([string]::IsNullOrWhiteSpace($PackageHash)) {
            if ($DryRun) { $PackageHash = 'dryrun' }
            else { throw '-PackageHash is required for a live (non -DryRun) run; supply the sha256 of the tested .nupkg.' }
        }

        $package = Find-GraphKitSmokePackage

        if ($DryRun -and $PackageHash -eq 'dryrun' -and $null -eq $package) {
            Write-Host 'SKIP  package digest: no package found in -DryRun; sentinel hash ''dryrun'' accepted' -ForegroundColor Yellow
            $summary.PackageHashVerified = 'Bypassed'
        }
        elseif ($null -eq $package) {
            throw 'No GraphKit package found (built .nupkg under output/, or an installed GraphKit module). Aborting before any live call.'
        }
        else {
            $null = Test-GraphKitSmokeDigest -ExpectedHash $PackageHash -ActualHash $package.Hash -PackagePath $package.Path
            $summary.PackageHashVerified = $true
            Write-Host ("PASS  package digest: {0} sha256 matches the expected digest" -f $package.Kind) -ForegroundColor Green
        }

        # 2. Resolve the profile into a context.
        if ($DryRun) {
            $context = [PSCustomObject]@{ PSTypeName = 'GraphKit.Context'; ProfileId = $ProfileId }
            Write-Host ("SKIP  profile resolution: -DryRun uses synthetic context '{0}'" -f $ProfileId) -ForegroundColor Yellow
        }
        else {
            if ([guid]::Empty -eq $AppId) { throw '-AppId is required for a live run (the lab mobile app used for the mutation).' }
            if ([guid]::Empty -eq $TestGroupId) { throw '-TestGroupId is required for a live run (the lab group the test assignment targets).' }
            Import-Module GraphKit -ErrorAction Stop
            $context = Get-GraphContext -ProfileId $ProfileId
            Write-Host ("PASS  resolved profile '{0}'" -f $ProfileId) -ForegroundColor Green
        }

        # 3-5. Select the transport and run the flow (read, capture, mutate, revert-in-finally).
        if ($DryRun) {
            if ($null -eq $TransportStub) {
                $transport = New-GraphKitSmokeDryRunTransport
            }
            else {
                $transport = $TransportStub
            }
        }
        else {
            $transport = New-GraphKitSmokeLiveTransport -Context $context -AppId $AppId
        }

        $flowSummary = Invoke-GraphKitSmokeFlow `
            -Context $context `
            -AppId $AppId `
            -TestGroupId $TestGroupId `
            -Transport $transport `
            -DeadlineUtc $startedUtc.AddMinutes($TimeoutMinutes) `
            -Trace $trace

        $summary.ReadOutcome = $flowSummary.ReadOutcome
        $summary.Mutation = $flowSummary.Mutation
        $summary.CleanupState = $flowSummary.CleanupState
        Write-Host 'SUCCESS' -ForegroundColor Green
    }
    catch {
        $exitCode = 1
        $summary.Error = $_.Exception.Message

        # The flow's finally recorded its cleanup decision into the trace (when the flow ran at
        # all); surface it honestly. An empty trace means the failure occurred before the mutation
        # flow, so there is no cleanup state to report.
        $cleanupState = $null
        if ($trace.Count -gt 0) {
            $lastCleanup = $trace | Where-Object { $_ -in @('revert', 'revert-failed', 'cleanup-skip') } | Select-Object -Last 1
            if ($null -ne $lastCleanup) {
                $cleanupState = switch ($lastCleanup) {
                    'revert'        { 'Reverted' }
                    'revert-failed' { 'RevertFailed' }
                    'cleanup-skip'  { 'NothingToRevert' }
                }
            }
        }

        if ($null -ne $cleanupState) {
            $summary.CleanupState = $cleanupState
            $summary.Mutation = [ordered]@{ Applied = $false; Reverted = ($cleanupState -eq 'Reverted') }
        }
        Write-Host ("FAIL  {0}" -f $_.Exception.Message) -ForegroundColor Red
    }
    finally {
        $summary.CompletedUtc = [datetime]::UtcNow.ToString('o')
        $safe = Protect-GraphKitSmokeSummary -InputObject $summary
        Write-Host ('SUMMARY ' + ($safe | ConvertTo-Json -Depth 6 -Compress))
    }

    exit $exitCode
}
