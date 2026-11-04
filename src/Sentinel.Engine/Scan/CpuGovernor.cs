using System.Diagnostics;

namespace Sentinel.Engine.Scan;

// Clock abstraction so pacing math is unit-testable exactly.
// Wall time MUST be monotonic (Stopwatch), never DateTime.
public interface ICpuClock
{
    int ProcessorCount { get; }

    long WallMilliseconds { get; }

    double CpuMilliseconds { get; }
}

public sealed class ProcessCpuClock : ICpuClock
{
    private readonly Process _process;
    private readonly Stopwatch _wall = Stopwatch.StartNew();

    public ProcessCpuClock() : this(Process.GetCurrentProcess())
    {
    }

    public ProcessCpuClock(Process process)
    {
        _process = process;
    }

    public int ProcessorCount => Environment.ProcessorCount;

    public long WallMilliseconds => _wall.ElapsedMilliseconds;

    public double CpuMilliseconds
    {
        get
        {
            _process.Refresh();
            return _process.TotalProcessorTime.TotalMilliseconds;
        }
    }
}

// Keeps THIS process at or under a CPU cap (% of TOTAL capacity,
// Task Manager units: 100% = all cores). Conservative by design: it
// counts the whole process, not just the scanner threads.
//
// Design (P1-05): per-period ABSOLUTE burn cap, cgroup-style. Each
// 250ms period independently allows period*cores*cap% thread-ms;
// callers sleep their share of any overrun against the period's
// burn-down schedule. No debt is carried across periods.
//
// Why not "sleep the measured excess" (the pre-P1-05 design)?
// That controller provably stabilizes at (unpaced+cap)/2 — it
// paced 55% against a 20% cap on a quiet host and 24% against
// a 10% cap under contention (2026-10-31 probes): at the target
// burn rate no NEW excess accrues, so nothing sustains the sleep
// that maintains the target. An absolute per-period allowance
// has no such fixed point: burn beyond the allowance always
// sleeps, whether the host is quiet or contended.
public sealed class CpuGovernor
{
    private const double PeriodMs = 250.0;
    private const double MaxSleepPerCallMs = 250.0;

    private readonly int _capPercent;
    private readonly ICpuClock _clock;
    private readonly object _gate = new();
    private long _periodStartMs;
    private double _cpuStartMs;
    private long _parkCount;

    public CpuGovernor(int capPercent) : this(capPercent, new ProcessCpuClock())
    {
    }

    public CpuGovernor(int capPercent, ICpuClock clock)
    {
        if (capPercent is < 1 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(capPercent));
        }

        _capPercent = capPercent;
        _clock = clock;
        _periodStartMs = clock.WallMilliseconds;
        _cpuStartMs = clock.CpuMilliseconds;
    }

    public int CapPercent => _capPercent;

    public async Task PaceAsync(CancellationToken ct = default)
    {
        double sleepMs;
        lock (_gate)
        {
            long now = _clock.WallMilliseconds;
            double cpuNow = _clock.CpuMilliseconds;
            double elapsed = now - _periodStartMs;
            if (elapsed >= PeriodMs)
            {
                // Roll the period from NOW (periods drift rather than
                // rewinding, so no phantom allowance accrues).
                _periodStartMs = now;
                _cpuStartMs = cpuNow;
                elapsed = 0;
                cpuNow = _cpuStartMs;
            }

            double allowed = PeriodMs * _clock.ProcessorCount * _capPercent / 100.0;
            double allowedSoFar = allowed * (elapsed / PeriodMs);
            double consumed = cpuNow - _cpuStartMs;
            double over = consumed - allowedSoFar;
            // The overrun is GLOBAL thread-ms; each paced caller
            // sleeps its per-core share. Exact when paced threads ≈
            // cores; self-correcting otherwise (a persisting overrun
            // keeps every caller sleeping). Unpaced co-tenants (UI,
            // GC, other tests) push the process over the cap only by
            // what THEY burn — paced threads absorb the correction.
            // Park to the period boundary on overrun (at least the
            // per-core share of it). Sleeping only the share
            // under-sleeps against chunky callers: every thread's
            // check-then-burn race lands one more chunk per period,
            // which summed across all threads re-overshoots the
            // allowance every period (measured: 17% steady at cap
            // 10). Parking converts bursts into a uniform duty
            // cycle whose steady state holds at/under the cap.
            //
            // A10 de-herding: parking every thread to the SAME
            // boundary synchronizes wake-ups, and identical chunked
            // callers then burn in lockstep and re-overshoot every
            // period anyway (measured: 37.6% steady at cap 15 on
            // quiet hardware, bipolar 5–99% sample series). The
            // deterministic 0/16/32/48ms stride smears wake times:
            // consecutive parkers always differ by >= 16ms, which
            // clears both the ~2ms timer wake slop and the 15.6ms
            // DateTime quantum that otherwise re-quantizes chunks
            // onto the same edge. No Random: the sequence is fully
            // deterministic, so the math tests stay exact.
            sleepMs = over > 0
                ? Math.Min(Math.Max(over / _clock.ProcessorCount, PeriodMs - elapsed) + DeherdOffsetMs(), MaxSleepPerCallMs)
                : 0;
        }

        if (sleepMs > 0)
        {
            // 1ms floor: (int) truncation would otherwise turn every
            // sub-millisecond correction into no correction at all.
            await Task.Delay(Math.Max(1, (int)sleepMs), ct).ConfigureAwait(false);
        }
    }

    // Called under _gate. Cyclic 16/32/48/0ms: consecutive parkers
    // (the ones that would otherwise wake in lockstep) always land
    // on different offsets.
    private long DeherdOffsetMs()
    {
        return (++_parkCount % 4) * 16;
    }
}
