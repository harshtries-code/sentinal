using System.Diagnostics;

namespace Sentinel.Engine.Scan;

// 03 §5 process priority, scoped: the scan lowers the whole process
// to BelowNormal while locked work runs and restores the exact prior
// level on dispose. Best effort throughout — a priority failure must
// never fail a scan (the CpuGovernor still enforces the cap).
//
// Why process-wide and not per-worker-thread: the scan pump runs on
// pool threads, and a pool thread between awaits can serve any other
// work; stamping it low would leak the priority onto unrelated
// continuations (including UI and test work). A dedicated-thread pump
// is the future shape if measurements demand finer control (A10 run
// record); BelowNormal is the standard background-scan answer.
public sealed class ScanProcessPriorityScope : IDisposable
{
    private readonly ProcessPriorityClass _prior;
    private readonly bool _lowered;
    private bool _disposed;

    public ScanProcessPriorityScope()
    {
        ProcessPriorityClass prior;
        try
        {
            using var self = Process.GetCurrentProcess();
            prior = self.PriorityClass;
        }
        catch
        {
            prior = ProcessPriorityClass.Normal;
        }

        _prior = prior;
        // Only ever lower: a process already at Idle/BelowNormal is
        // left untouched (setting BelowNormal unconditionally would
        // RAISE an Idle process).
        bool shouldLower = prior is ProcessPriorityClass.Normal
            or ProcessPriorityClass.AboveNormal
            or ProcessPriorityClass.High
            or ProcessPriorityClass.RealTime;
        _lowered = shouldLower && TrySet(ProcessPriorityClass.BelowNormal);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_lowered)
        {
            TrySet(_prior);
        }
    }

    private static bool TrySet(ProcessPriorityClass level)
    {
        try
        {
            using var self = Process.GetCurrentProcess();
            if (self.PriorityClass == level)
            {
                return true;
            }

            self.PriorityClass = level;
            return true;
        }
        catch
        {
            return false;
        }
    }
}
