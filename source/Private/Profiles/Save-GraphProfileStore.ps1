<#
    Private: atomically persist the profile store, plus the interprocess lock
    helpers used by read-modify-write callers.

    Save-GraphProfileStore writes to a temporary file in the same directory,
    flushes it to disk, then renames it over the original. The previous
    generation is retained as profiles.json.bak so a half-written store is never
    observed and a failed write can be recovered from.

    The lock helpers serialize read-modify-write across pwsh sessions: a
    FileStream opened with FileShare.None on a .lock sidecar, with a bounded
    retry before an actionable error.
#>

function Enter-GraphProfileStoreLock {
    [CmdletBinding()]
    [OutputType([System.IO.FileStream])]
    param(
        [Parameter(Mandatory)]
        [string] $StorePath
    )

    $lockPath = "$StorePath.lock"
    $maxAttempts = 10

    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            return [System.IO.File]::Open(
                $lockPath,
                [System.IO.FileMode]::OpenOrCreate,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None
            )
        }
        catch {
            if ($attempt -ge $maxAttempts) {
                break
            }
            Start-Sleep -Milliseconds 100
        }
    }

    throw "Could not acquire the profile store lock at '$lockPath' after $maxAttempts attempts (10 x 100 ms). Another GraphKit process may be writing '$StorePath'; retry once it completes."
}

function Exit-GraphProfileStoreLock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.FileStream] $Lock
    )

    if ($null -ne $Lock) {
        $Lock.Dispose()
    }
}

function Save-GraphProfileStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Store,

        [Parameter(Mandatory)]
        [string] $StorePath
    )

    $directory = Split-Path -Parent $StorePath
    if (-not [string]::IsNullOrEmpty($directory) -and -not (Test-Path -LiteralPath $directory -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }

    $json = $Store | ConvertTo-Json -Depth 20
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)

    $tempPath = "$StorePath.tmp.$PID.$([guid]::NewGuid().ToString('N'))"

    $stream = [System.IO.File]::Open(
        $tempPath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None
    )
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }

    try {
        if (Test-Path -LiteralPath $StorePath -PathType Leaf) {
            [System.IO.File]::Copy($StorePath, "$StorePath.bak", $true)
        }
        [System.IO.File]::Move($tempPath, $StorePath, $true)
    }
    catch {
        if (Test-Path -LiteralPath $tempPath -PathType Leaf) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
        throw
    }
}
