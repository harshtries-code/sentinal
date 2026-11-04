using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using Sentinel.App.Services;
using Sentinel.Store;

namespace Sentinel.App.ViewModels;

// Status bar data (02 §2): our own CPU/RAM, Defender service state,
// and the last recorded scan. All read-only.
// P27: IO is cumulative MB read/written since launch (self
// process counters, clamped at zero on counter reset). Optional
// so older constructions keep compiling.
public sealed record ResourceSample(
    DateTime AtUtc, double CpuPercent, double RamMb,
    double IoReadMb = 0, double IoWriteMb = 0);

public sealed class StatusBarViewModel : ViewModelBase, IDisposable
{
    // 30 minutes at the 2s UI cadence. Oldest-first; the
    // Performance page slices it by range (board 03).
    private const int MaxSamples = 900;
    private readonly Process _self;
    private readonly Func<string> _dbPath;
    private readonly Queue<ResourceSample> _history = new();
    private TimeSpan _lastCpu;
    private DateTime _lastSample;
    private readonly long _launchReadBytes;
    private readonly long _launchWriteBytes;
    private double _currentCpuPercent;
    private double _currentRamMb;
    private string _selfResources = "—";
    private string _defenderState = "—";
    private string _lastScan = "Never scanned";
    private string _watchLine = "Watch: off";
    private bool _disposed;

    public StatusBarViewModel(Func<string>? dbPath = null)
    {
        _self = Process.GetCurrentProcess();
        _dbPath = dbPath ?? (() => SentinelPaths.DatabasePath);
        _lastCpu = _self.TotalProcessorTime;
        _lastSample = DateTime.UtcNow;
        _launchReadBytes = IoCounter(c => c.ReadTransferCount);
        _launchWriteBytes = IoCounter(c => c.WriteTransferCount);
    }

    public string SelfResources
    {
        get => _selfResources;
        private set => Set(ref _selfResources, value);
    }

    public string DefenderState
    {
        get => _defenderState;
        private set => Set(ref _defenderState, value);
    }

    public string LastScan
    {
        get => _lastScan;
        private set => Set(ref _lastScan, value);
    }

    // P21 (03 §4): the watcher's own line, refreshed on the same
    // 2s cadence. The provider is set by MainViewModel; without
    // it the line stays honestly off.
    public Func<string>? WatchLineProvider { get; set; }

    public string WatchLine
    {
        get => _watchLine;
        private set => Set(ref _watchLine, value);
    }

    public double CurrentCpuPercent
    {
        get => _currentCpuPercent;
        private set => Set(ref _currentCpuPercent, value);
    }

    public double CurrentRamMb
    {
        get => _currentRamMb;
        private set => Set(ref _currentRamMb, value);
    }

    // Snapshot copy: safe to hand to a background collect.
    public IReadOnlyList<ResourceSample> SampleHistory()
    {
        return _history.ToList();
    }

    // Called on a 2s UI timer. Cheap by design: one refresh + one query.
    public void Refresh()
    {
        // A09: a queued tick racing OnClosed must not touch the
        // disposed process handle (ObjectDisposedException).
        if (_disposed)
        {
            return;
        }

        _self.Refresh();
        var now = DateTime.UtcNow;
        var cpu = _self.TotalProcessorTime;
        var wallMs = Math.Max(1.0, (now - _lastSample).TotalMilliseconds);
        var percent = (cpu - _lastCpu).TotalMilliseconds / (wallMs * Environment.ProcessorCount) * 100.0;
        _lastCpu = cpu;
        _lastSample = now;
        var ramMb = _self.WorkingSet64 / 1024.0 / 1024.0;
        // P27: session IO from the self counters. ReadBytes and
        // WriteBytes include everything the process touched (DB,
        // pagefile, pipes) — labelled as session totals, never as
        // disk-device load.
        double readMb = Math.Max(0, (IoCounter(c => c.ReadTransferCount) - _launchReadBytes) / 1024.0 / 1024.0);
        double writeMb = Math.Max(0, (IoCounter(c => c.WriteTransferCount) - _launchWriteBytes) / 1024.0 / 1024.0);
        SelfResources = $"Sentinel {percent:F1}% CPU · {ramMb:F0} MB";
        CurrentCpuPercent = percent;
        CurrentRamMb = ramMb;
        _history.Enqueue(new ResourceSample(now, percent, ramMb, readMb, writeMb));
        while (_history.Count > MaxSamples)
        {
            _history.Dequeue();
        }

        DefenderState = ReadDefenderState();
        LastScan = ReadLastScan();
        if (WatchLineProvider is not null)
        {
            try
            {
                WatchLine = WatchLineProvider();
            }
            catch
            {
                WatchLine = "Watch: unavailable";
            }
        }
    }

    // P27: self IO via GetProcessIoCounters (Process exposes
    // no IO counters). Any failure reads as zero — unknown IO is
    // "no session IO yet", never a crash.
    private long IoCounter(Func<IO_COUNTERS, ulong> pick)
    {
        try
        {
            if (NativeIo.GetProcessIoCounters(_self.Handle, out var counters))
            {
                ulong value = pick(counters);
                return value > long.MaxValue ? long.MaxValue : (long)value;
            }
        }
        catch
        {
        }

        return 0;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    private static class NativeIo
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetProcessIoCounters(IntPtr hProcess, out IO_COUNTERS counters);
    }

    private static string ReadDefenderState()
    {
        try
        {
            using var svc = new ServiceController("WinDefend");
            return $"Defender service: {svc.Status}";
        }
        catch
        {
            return "Defender service: unknown";
        }
    }

    private string ReadLastScan()
    {
        try
        {
            var path = _dbPath();
            if (!File.Exists(path))
            {
                return "Never scanned";
            }

            using var db = new SentinelDb(path);
            return db.GetMaxGeneration() == 0
                ? "Never scanned"
                : $"Scan generation {db.GetMaxGeneration()}";
        }
        catch
        {
            return "Scan history unreadable";
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _self.Dispose();
    }
}
