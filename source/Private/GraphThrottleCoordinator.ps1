# GraphThrottleCoordinator — scoped, thread-safe throttle state with AIMD admission control.
#
# Graph enforces overlapping service/tenant/application/operation/request-type limits, so
# throttle state must be scoped (coarse + leaf gates), never one process-wide timestamp.
# This coordinator holds one mutable state record per scope key in a thread-safe
# ConcurrentDictionary and applies additive-increase/multiplicative-decrease admission
# control: a qualified 429/503 cuts the permitted concurrency to the floor and applies the
# server-directed cooldown; sustained success restores concurrency one slot at a time.
#
# The coordinator is a small COMPILED type (not a PowerShell class). This is deliberate:
# PowerShell class methods are not reliably invocable from concurrent runspaces — locks
# taken inside them lose mutual exclusion and nested method calls deadlock (verified
# empirically while building the concurrency suite). The design spec sanctions a "small
# compiled type" for exactly this shared, thread-safe state. The compiled type is created
# once per session via Add-Type and held as a module-scoped lazy singleton.

if ($null -eq ('GraphThrottleCoordinator' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;

public sealed class GraphThrottleScopeState
{
    private readonly object _sync = new object();
    private DateTime _cooldownUntilUtc = DateTime.MinValue;
    private int _maxConcurrent;
    private int _inFlight;
    private int _successStreak;
    private readonly int _floor;
    private readonly int _cap;
    private readonly int _streakThreshold;

    public GraphThrottleScopeState(int maxConcurrent, int floor, int cap, int streakThreshold)
    {
        _maxConcurrent = Math.Max(1, maxConcurrent);
        _floor = Math.Max(1, floor);
        _cap = Math.Max(1, cap);
        _streakThreshold = Math.Max(1, streakThreshold);
    }

    public int MaxConcurrent
    {
        get { lock (_sync) { return _maxConcurrent; } }
        set { lock (_sync) { _maxConcurrent = Math.Max(1, value); } }
    }

    public int InFlight { get { lock (_sync) { return _inFlight; } } }
    public int SuccessStreak { get { lock (_sync) { return _successStreak; } } }
    public DateTime CooldownUntilUtc { get { lock (_sync) { return _cooldownUntilUtc; } } }

    public long GetWaitMilliseconds(DateTime utcNow)
    {
        lock (_sync)
        {
            if (_cooldownUntilUtc <= utcNow) return 0;
            return (long)Math.Ceiling((_cooldownUntilUtc - utcNow).TotalMilliseconds);
        }
    }

    // Non-throwing admission attempt. Wait-GraphThrottleGate polls this so a caller
    // that finds every slot busy WAITS rather than failing: admission control that
    // throws when concurrency is squeezed to the floor fails precisely when it is
    // doing its job.
    public bool TryAcquire()
    {
        lock (_sync)
        {
            if (_inFlight >= _maxConcurrent) return false;
            _inFlight++;
            return true;
        }
    }

    // Retained for callers that have already established a free slot. Prefer
    // TryAcquire; this throws when the caller was wrong.
    public void Acquire()
    {
        lock (_sync)
        {
            if (_inFlight >= _maxConcurrent)
            {
                throw new InvalidOperationException(
                    "Throttle admission denied: " + _inFlight + " of " + _maxConcurrent +
                    " slots already in use. Callers must pass Wait-GraphThrottleGate before acquiring admission.");
            }
            _inFlight++;
        }
    }

    public void Release(bool success)
    {
        lock (_sync)
        {
            if (_inFlight > 0) _inFlight--;
            if (success) AdditiveIncrease();
        }
    }

    public void ApplyCooldown(int retryAfterSeconds, DateTime utcNow)
    {
        lock (_sync)
        {
            int seconds = Math.Max(0, retryAfterSeconds);
            DateTime until = utcNow.AddSeconds(seconds);
            if (until > _cooldownUntilUtc) _cooldownUntilUtc = until;
        }
    }

    public void RecordThrottle(bool qualified, int retryAfterSeconds, DateTime utcNow)
    {
        lock (_sync)
        {
            if (qualified) _maxConcurrent = _floor;
            _successStreak = 0;
            int seconds = Math.Max(0, retryAfterSeconds);
            DateTime until = utcNow.AddSeconds(seconds);
            if (until > _cooldownUntilUtc) _cooldownUntilUtc = until;
        }
    }

    public void RecordSuccess()
    {
        lock (_sync) { AdditiveIncrease(); }
    }

    private void AdditiveIncrease()
    {
        _successStreak++;
        if (_successStreak >= _streakThreshold)
        {
            if (_maxConcurrent < _cap) _maxConcurrent++;
            _successStreak = 0;
        }
    }
}

public sealed class GraphThrottleCoordinator
{
    private readonly ConcurrentDictionary<string, GraphThrottleScopeState> _states =
        new ConcurrentDictionary<string, GraphThrottleScopeState>();

    private const int Floor = 1;
    private const int InitialConcurrency = 2;
    private const int Cap = 8;
    private const int StreakThreshold = 5;

    private GraphThrottleScopeState GetOrCreate(string scopeKey)
    {
        // Begin conservatively and ramp, per the spec's AIMD guidance: "begin
        // conservatively ... restore concurrency gradually after successful requests".
        // Starting at Cap meant the very first burst against a cold scope ran at full
        // concurrency, which is the throttle wave admission control exists to avoid -
        // and the scope is coldest exactly when a run starts, i.e. when a burst is most
        // likely. Sustained success still reaches Cap via AdditiveIncrease.
        return _states.GetOrAdd(scopeKey, key => new GraphThrottleScopeState(InitialConcurrency, Floor, Cap, StreakThreshold));
    }

    public long GetWaitMilliseconds(string scopeKey, DateTime utcNow)
    {
        GraphThrottleScopeState state;
        return _states.TryGetValue(scopeKey, out state) ? state.GetWaitMilliseconds(utcNow) : 0;
    }

    public void AcquireAdmission(string scopeKey) { GetOrCreate(scopeKey).Acquire(); }
    public bool TryAcquireAdmission(string scopeKey) { return GetOrCreate(scopeKey).TryAcquire(); }
    public void ReleaseAdmission(string scopeKey, bool success) { GetOrCreate(scopeKey).Release(success); }
    public void ApplyCooldown(string scopeKey, int retryAfterSeconds, DateTime utcNow) { GetOrCreate(scopeKey).ApplyCooldown(retryAfterSeconds, utcNow); }
    public void RecordThrottle(string scopeKey, bool qualified, int retryAfterSeconds, DateTime utcNow) { GetOrCreate(scopeKey).RecordThrottle(qualified, retryAfterSeconds, utcNow); }
    public void RecordSuccess(string scopeKey) { GetOrCreate(scopeKey).RecordSuccess(); }

    // Inspection surface for tests and diagnostics. State is never persisted.
    public int GetMaxConcurrent(string scopeKey) { GraphThrottleScopeState s; return _states.TryGetValue(scopeKey, out s) ? s.MaxConcurrent : 0; }
    public int GetInFlight(string scopeKey) { GraphThrottleScopeState s; return _states.TryGetValue(scopeKey, out s) ? s.InFlight : 0; }
    public int GetSuccessStreak(string scopeKey) { GraphThrottleScopeState s; return _states.TryGetValue(scopeKey, out s) ? s.SuccessStreak : 0; }
    public DateTime GetCooldownUntilUtc(string scopeKey) { GraphThrottleScopeState s; return _states.TryGetValue(scopeKey, out s) ? s.CooldownUntilUtc : DateTime.MinValue; }
    public bool ContainsKey(string scopeKey) { return _states.ContainsKey(scopeKey); }
    public bool IsEmpty { get { return _states.IsEmpty; } }
    public void SetMaxConcurrent(string scopeKey, int maxConcurrent) { GetOrCreate(scopeKey).MaxConcurrent = maxConcurrent; }
}
'@
}

# Module-scoped singleton, created lazily on first use. State lives only for the lifetime
# of the module session; it is never persisted.
$script:GraphKitThrottleCoordinator = $null

function Get-GraphThrottleCoordinator {
    [CmdletBinding()]
    param()

    if ($null -eq $script:GraphKitThrottleCoordinator) {
        $script:GraphKitThrottleCoordinator = New-Object -TypeName GraphThrottleCoordinator
    }

    return $script:GraphKitThrottleCoordinator
}
