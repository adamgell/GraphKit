<#
    Hostile Retry-After parser.

    Graph has been observed returning malformed values such as "Retry-After: 30,120",
    which breaks parsers expecting a single integer. Ordered rules, per spec:

      1. Handle multiple header values supplied as a collection.
      2. Try the whole value as delta-seconds.
      3. Try the whole value as an HTTP date.
      4. Only then consider a malformed comma-separated numeric list.
      5. Parse x-ms-retry-after-ms separately.
      6. Choose a conservative valid delay (maximum is reasonable policy).
      7. Clamp negative and excessive values, and record that the header was malformed.

    NEVER split on commas before attempting an HTTP-date parse - valid HTTP dates
    contain a comma ("Wed, 21 Oct 2015 07:28:00 GMT"). For HTTP-date delays the
    delta is computed against the response Date header when present so workstation
    clock skew cannot shorten a server-directed delay.

    When no usable header exists (a 429 with no Retry-After), jittered exponential
    backoff is computed: base seconds doubling per attempt, capped, jittered.
#>
function Get-GraphRetryDelay {
    [CmdletBinding()]
    param(
        # Retry-After header value(s): string, integer, or a collection of them.
        [AllowNull()]
        [object] $RetryAfterValues,

        # x-ms-retry-after-ms value (milliseconds), parsed separately.
        [AllowNull()]
        [object] $XmsRetryAfterMs,

        # Response Date header, used as the reference for HTTP-date delays.
        [AllowNull()]
        [object] $ResponseDate,

        # Current clock, used as the reference when no Date header is present.
        [datetime] $UtcNow = [datetime]::UtcNow,

        # Attempt number (1-based), used only for exponential backoff.
        [ValidateRange(1, 1000)]
        [int] $Attempt = 1,

        # Scriptblock returning a [double] in [0,1], used only for backoff jitter.
        [scriptblock] $Jitter,

        [ValidateRange(1, 86400)]
        [int] $MaximumAcceptedSeconds = 120,

        [ValidateRange(1, 3600)]
        [int] $BaseDelaySeconds = 1
    )

    $malformed = $false
    $candidates = [System.Collections.Generic.List[object]]::new()

    $reference = if ($ResponseDate -is [datetime]) { ([datetime] $ResponseDate).ToUniversalTime() } else { $UtcNow.ToUniversalTime() }

    $values = @()
    if ($null -ne $RetryAfterValues) {
        if ($RetryAfterValues -is [System.Collections.IEnumerable] -and $RetryAfterValues -isnot [string]) {
            $values = @($RetryAfterValues)
        }
        else {
            $values = @($RetryAfterValues)
        }
    }

    foreach ($raw in $values) {
        if ($null -eq $raw) { continue }

        $s = ([string] $raw).Trim()
        if ([string]::IsNullOrEmpty($s)) { continue }

        # 2. Whole value as delta-seconds.
        if ($s -match '^-?\d+$') {
            $candidates.Add([pscustomobject] @{ Seconds = [double] $s; Source = 'RetryAfterDelta' })
            continue
        }

        # 3. Whole value as an HTTP date (BEFORE any comma split).
        $parsedDate = [System.DateTimeOffset]::MinValue
        if ([System.DateTimeOffset]::TryParse(
                $s,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::AllowWhiteSpaces,
                [ref] $parsedDate)) {
            $delta = ($parsedDate.UtcDateTime - $reference).TotalSeconds
            if ($delta -lt 0) { $delta = 0 }
            $candidates.Add([pscustomobject] @{ Seconds = $delta; Source = 'RetryAfterDate' })
            continue
        }

        # 4. Only now: malformed comma-separated numeric list.
        $parts = $s -split ','
        $nums = [System.Collections.Generic.List[double]]::new()
        $allNumeric = $true
        foreach ($part in $parts) {
            $pt = $part.Trim()
            if ($pt -match '^-?\d+$') {
                $nums.Add([double] $pt)
            }
            else {
                $allNumeric = $false
                break
            }
        }

        $malformed = $true
        if ($allNumeric -and $nums.Count -gt 0) {
            $max = 0.0
            foreach ($n in $nums) { if ($n -gt $max) { $max = $n } }
            $candidates.Add([pscustomobject] @{ Seconds = $max; Source = 'RetryAfterList' })
        }
    }

    # 5. x-ms-retry-after-ms, separately.
    if ($null -ne $XmsRetryAfterMs) {
        $msText = ([string] $XmsRetryAfterMs).Trim()
        if ($msText -match '^-?\d+$') {
            $candidates.Add([pscustomobject] @{ Seconds = ([double] $msText / 1000.0); Source = 'XmsRetryAfterMs' })
        }
        else {
            $malformed = $true
        }
    }

    $delaySeconds = 0.0
    $source = 'ExponentialBackoff'

    if ($candidates.Count -gt 0) {
        # 6. Conservative maximum of candidates.
        $maxCandidate = $null
        foreach ($c in $candidates) {
            if ($null -eq $maxCandidate -or $c.Seconds -gt $maxCandidate.Seconds) {
                $maxCandidate = $c
            }
        }

        $delaySeconds = $maxCandidate.Seconds
        $source = $maxCandidate.Source
    }
    else {
        # No usable header: jittered exponential backoff.
        $computed = [Math]::Min(
            [double] $MaximumAcceptedSeconds,
            [double] $BaseDelaySeconds * [Math]::Pow(2.0, $Attempt - 1)
        )

        $jitterFactor = 1.0
        if ($null -ne $Jitter) {
            $jitterValue = & $Jitter
            if ($null -ne $jitterValue) {
                $jitterFactor = [double] $jitterValue
            }
        }

        $delaySeconds = $computed * $jitterFactor
    }

    # 7. Clamp negative and excessive values.
    $delaySeconds = [Math]::Max(0.0, [Math]::Min([double] $MaximumAcceptedSeconds, $delaySeconds))

    return [pscustomobject] @{
        DelaySeconds = [Math]::Round($delaySeconds, 3)
        Source       = $source
        Malformed    = $malformed
    }
}
