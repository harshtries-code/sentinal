using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Sentinel.Engine.Agent;
using Sentinel.Engine.Scan;
using Xunit;

namespace Sentinel.Tests;

// A10: power admission/continuity (03 §5, 05 §6), process priority
// scoping, and pause/cancel latency. All power tests run against
// fake probes — deterministic, no battery hardware needed.
public sealed class ScanPowerTests : IDisposable
{
    private readonly string _root;
    private readonly string _dbPath;
    private bool _disposed;

    public ScanPowerTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "sentinel-power-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
        var payload = new byte[4096];
        new Random(7).NextBytes(payload);
        for (int i = 0; i < 20; i++)
        {
            File.WriteAllBytes(Path.Combine(_root, $"f{i:D3}.bin"), payload);
        }

        _dbPath = Path.Combine(Path.GetTempPath(), "sentinel-power-" + Guid.NewGuid().ToString("N") + ".db");
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        try { Directory.Delete(_root, recursive: true); } catch { }
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch { }
        }
    }

    private sealed class FixedIdleProbe(TimeSpan idle) : IIdleProbe
    {
        public TimeSpan GetIdleTime() => idle;
    }

    private sealed class FixedFullscreenProbe(bool fullscreen) : IFullscreenProbe
    {
        public bool IsForegroundFullscreen() => fullscreen;
    }

    private sealed class FixedBatteryProbe(PowerState state) : IBatteryProbe
    {
        public PowerState GetPowerState() => state;
    }

    private sealed class MutableBatteryProbe(PowerState initial) : IBatteryProbe
    {
        private readonly object _gate = new();
        private PowerState _state = initial;

        public PowerState GetPowerState()
        {
            lock (_gate)
            {
                return _state;
            }
        }

        public void Set(PowerState next)
        {
            lock (_gate)
            {
                _state = next;
            }
        }
    }

    // Call #1 is admission; calls #2..N report saver stress; then AC.
    // Single Eco worker => fixed call sequence (CountingIdleProbe precedent).
    private sealed class CountingBatteryProbe(int stressedUntilCall) : IBatteryProbe
    {
        private static readonly PowerState Saver = new(true, true, true, 50);
        private int _calls;

        public PowerState GetPowerState()
        {
            int call = Interlocked.Increment(ref _calls);
            return call > 1 && call <= stressedUntilCall ? Saver : PowerState.AcPower;
        }
    }

    private static readonly PowerState Saver = new(Known: true, BatterySaverOn: true, OnBattery: true, BatteryPercent: 50);
    private static readonly PowerState LowBattery = new(Known: true, BatterySaverOn: false, OnBattery: true, BatteryPercent: 10);
    private static readonly PowerState ChargingLow = new(Known: true, BatterySaverOn: false, OnBattery: false, BatteryPercent: 10);

    private ScanOrchestrator EcoOrchestrator(IBatteryProbe battery, string? dbPath = null)
    {
        var db = new Sentinel.Store.SentinelDb(dbPath ?? _dbPath);
        return new ScanOrchestrator(
            db,
            idle: new FixedIdleProbe(TimeSpan.FromMinutes(30)),
            fullscreen: new FixedFullscreenProbe(false),
            battery: battery);
    }

    [Fact]
    public async Task Eco_Refused_On_BatterySaver()
    {
        using var db = new Sentinel.Store.SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(
            db,
            idle: new FixedIdleProbe(TimeSpan.FromMinutes(30)),
            fullscreen: new FixedFullscreenProbe(false),
            battery: new FixedBatteryProbe(Saver));

        var result = await orchestrator.RunAsync(
            new ScanOptions(ScanMode.Eco, [_root]), new PauseToken());

        Assert.Equal(ScanOutcome.RefusedLowPower, result.Outcome);
        Assert.Contains("battery saver", result.RefusalReason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Eco_Refused_On_LowBattery()
    {
        using var db = new Sentinel.Store.SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(
            db,
            idle: new FixedIdleProbe(TimeSpan.FromMinutes(30)),
            fullscreen: new FixedFullscreenProbe(false),
            battery: new FixedBatteryProbe(LowBattery));

        var result = await orchestrator.RunAsync(
            new ScanOptions(ScanMode.Eco, [_root]), new PauseToken());

        Assert.Equal(ScanOutcome.RefusedLowPower, result.Outcome);
        Assert.Contains("battery is low", result.RefusalReason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Eco_Refused_When_Power_Unknown()
    {
        using var db = new Sentinel.Store.SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(
            db,
            idle: new FixedIdleProbe(TimeSpan.FromMinutes(30)),
            fullscreen: new FixedFullscreenProbe(false),
            battery: new FixedBatteryProbe(PowerState.Unknown));

        var result = await orchestrator.RunAsync(
            new ScanOptions(ScanMode.Eco, [_root]), new PauseToken());

        Assert.Equal(ScanOutcome.RefusedLowPower, result.Outcome);
    }

    [Fact]
    public async Task Eco_Allowed_On_AC_And_While_Charging()
    {
        // 10% on the charger is charging, not stressed.
        var battery = new MutableBatteryProbe(PowerState.AcPower);
        using var db = new Sentinel.Store.SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(
            db,
            idle: new FixedIdleProbe(TimeSpan.FromMinutes(30)),
            fullscreen: new FixedFullscreenProbe(false),
            battery: battery);

        var ac = await orchestrator.RunAsync(
            new ScanOptions(ScanMode.Eco, [_root]), new PauseToken());
        Assert.Equal(ScanOutcome.Completed, ac.Outcome);

        battery.Set(ChargingLow);
        var charging = await orchestrator.RunAsync(
            new ScanOptions(ScanMode.Eco, [_root]), new PauseToken());
        Assert.Equal(ScanOutcome.Completed, charging.Outcome);
    }

    [Fact]
    public async Task Balanced_Never_Refused_On_Power()
    {
        // Explicit user starts are never refused: saver never gates
        // Balanced at all, and low battery only pauses (setting off
        // here, so not even that).
        using var db = new Sentinel.Store.SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(
            db,
            idle: new FixedIdleProbe(TimeSpan.Zero),
            fullscreen: new FixedFullscreenProbe(true),
            battery: new FixedBatteryProbe(Saver),
            pauseOnLowBattery: false);

        var result = await AwaitGuarded(orchestrator.RunAsync(
            new ScanOptions(ScanMode.Balanced, [_root]), new PauseToken()));

        Assert.Equal(ScanOutcome.Completed, result.Outcome);
        Assert.Equal(20, result.FilesSeen);
    }

    [Fact]
    public async Task Balanced_Pauses_On_LowBattery_While_Setting_On()
    {
        var battery = new MutableBatteryProbe(LowBattery);
        using var db = new Sentinel.Store.SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(
            db,
            idle: new FixedIdleProbe(TimeSpan.Zero),
            fullscreen: new FixedFullscreenProbe(false),
            battery: battery,
            pauseOnLowBattery: true);

        var run = orchestrator.RunAsync(
            new ScanOptions(ScanMode.Balanced, [_root]), new PauseToken());

        await Task.Delay(1200);
        Assert.False(run.IsCompleted); // Still waiting out low battery.

        battery.Set(PowerState.AcPower);
        var result = await AwaitGuarded(run);
        Assert.Equal(ScanOutcome.Completed, result.Outcome);
        Assert.Equal(20, result.FilesSeen);
    }

    [Fact]
    public async Task Balanced_Ignores_LowBattery_When_Setting_Off()
    {
        using var db = new Sentinel.Store.SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(
            db,
            idle: new FixedIdleProbe(TimeSpan.Zero),
            fullscreen: new FixedFullscreenProbe(false),
            battery: new FixedBatteryProbe(LowBattery),
            pauseOnLowBattery: false);

        var result = await AwaitGuarded(orchestrator.RunAsync(
            new ScanOptions(ScanMode.Balanced, [_root]), new PauseToken()));

        Assert.Equal(ScanOutcome.Completed, result.Outcome);
        Assert.Equal(20, result.FilesSeen);
    }

    [Fact]
    public async Task Eco_Continuity_Waits_Out_BatterySaver()
    {
        using var db = new Sentinel.Store.SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(
            db,
            idle: new FixedIdleProbe(TimeSpan.FromMinutes(30)),
            fullscreen: new FixedFullscreenProbe(false),
            battery: new CountingBatteryProbe(stressedUntilCall: 4));
        var sw = Stopwatch.StartNew();

        var result = await AwaitGuarded(orchestrator.RunAsync(
            new ScanOptions(ScanMode.Eco, [_root]), new PauseToken()));

        sw.Stop();
        Assert.Equal(ScanOutcome.Completed, result.Outcome);
        Assert.Equal(20, result.FilesSeen);
        Assert.True(sw.ElapsedMilliseconds >= 900,
            "Eco scan must wait out battery saver instead of scanning through it.");
    }

    [Fact]
    public void PriorityScope_Lowers_And_Restores()
    {
        ProcessPriorityClass original;
        using (var self = Process.GetCurrentProcess())
        {
            original = self.PriorityClass;
        }

        using (var scope = new ScanProcessPriorityScope())
        {
            using var self = Process.GetCurrentProcess();
            // A process already at Idle/BelowNormal is untouched;
            // anything higher must read BelowNormal inside the scope.
            bool alreadyLow = original is ProcessPriorityClass.Idle
                or ProcessPriorityClass.BelowNormal;
            Assert.Equal(alreadyLow ? original : ProcessPriorityClass.BelowNormal, self.PriorityClass);
        }

        using (var self = Process.GetCurrentProcess())
        {
            Assert.Equal(original, self.PriorityClass);
        }
    }

    [Fact]
    public async Task Scan_Lowers_Process_Priority_Mid_Run()
    {
        // 100 files keep the locked scan alive long enough to sample.
        string dir = Path.Combine(Path.GetTempPath(), "sentinel-prio-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var payload = new byte[16384];
        new Random(11).NextBytes(payload);
        for (int i = 0; i < 100; i++)
        {
            File.WriteAllBytes(Path.Combine(dir, $"p{i:D3}.bin"), payload);
        }

        string dbPath = Path.Combine(Path.GetTempPath(), "sentinel-prio-" + Guid.NewGuid().ToString("N") + ".db");
        try
        {
            using var db = new Sentinel.Store.SentinelDb(dbPath);
            var orchestrator = new ScanOrchestrator(
                db,
                idle: new FixedIdleProbe(TimeSpan.FromMinutes(30)),
                fullscreen: new FixedFullscreenProbe(false),
                battery: new FixedBatteryProbe(PowerState.AcPower));

            ProcessPriorityClass original;
            using (var self = Process.GetCurrentProcess())
            {
                original = self.PriorityClass;
            }

            bool observedLow = false;
            var run = orchestrator.RunAsync(
                new ScanOptions(ScanMode.Balanced, [dir]), new PauseToken());
            while (!run.IsCompleted)
            {
                try
                {
                    using var self = Process.GetCurrentProcess();
                    if (self.PriorityClass == ProcessPriorityClass.BelowNormal)
                    {
                        observedLow = true;
                    }
                }
                catch
                {
                }

                await Task.Delay(10);
            }

            var result = await AwaitGuarded(run);
            Assert.Equal(ScanOutcome.Completed, result.Outcome);

            bool alreadyLow = original is ProcessPriorityClass.Idle
                or ProcessPriorityClass.BelowNormal;
            Assert.True(alreadyLow || observedLow,
                "Process priority must read BelowNormal at least once during a scan.");
            using (var self = Process.GetCurrentProcess())
            {
                Assert.Equal(original, self.PriorityClass);
            }
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
            foreach (var suffix in new[] { "", "-wal", "-shm" })
            {
                try { File.Delete(dbPath + suffix); } catch { }
            }
        }
    }

    [Fact]
    public async Task Pause_Stops_Worker_Intake_Within_One_Second()
    {
        // Progress-gated (not time-gated): pause only after the hub
        // proves 50+ files are done, so the test cannot pass or fail
        // on box speed. After Pause, each worker finishes at most its
        // in-flight file (Balanced = 2 workers), then blocks.
        const int files = 600;
        string dir = Path.Combine(Path.GetTempPath(), "sentinel-pause-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var payload = new byte[8192];
        new Random(13).NextBytes(payload);
        for (int i = 0; i < files; i++)
        {
            File.WriteAllBytes(Path.Combine(dir, $"w{i:D3}.bin"), payload);
        }

        string dbPath = Path.Combine(Path.GetTempPath(), "sentinel-pause-" + Guid.NewGuid().ToString("N") + ".db");
        try
        {
            using var db = new Sentinel.Store.SentinelDb(dbPath);
            var orchestrator = new ScanOrchestrator(
                db,
                idle: new FixedIdleProbe(TimeSpan.FromMinutes(30)),
                fullscreen: new FixedFullscreenProbe(false),
                battery: new FixedBatteryProbe(PowerState.AcPower));
            var pause = new PauseToken();
            var hub = new EvidencePreviewHub();

            var run = orchestrator.RunAsync(
                new ScanOptions(ScanMode.Balanced, [dir]), pause, CancellationToken.None, hub);

            var progressGuard = Stopwatch.StartNew();
            while (hub.Revision < 50 && !run.IsCompleted)
            {
                if (progressGuard.Elapsed > TimeSpan.FromSeconds(30))
                {
                    break;
                }

                await Task.Delay(20);
            }

            Assert.True(hub.Revision >= 50, "Scan must be demonstrably in flight before pausing.");
            Assert.True(hub.Revision < files, "Scan must not have finished before pausing.");

            pause.Pause();
            int revAtPause = hub.Revision;
            await Task.Delay(1000);
            int revAfterSecond = hub.Revision;
            Assert.True(revAfterSecond - revAtPause <= 3,
                $"Pause must bite within 1s; revision advanced {revAfterSecond - revAtPause} after pausing.");

            pause.Resume();
            var result = await AwaitGuarded(run);
            Assert.Equal(ScanOutcome.Completed, result.Outcome);
            Assert.Equal(files, result.FilesSeen);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
            foreach (var suffix in new[] { "", "-wal", "-shm" })
            {
                try { File.Delete(dbPath + suffix); } catch { }
            }
        }
    }

    [SkippableFact]
    public async Task Cancel_On_MultiGB_File_Returns_Within_One_Second()
    {
        // Sparse 2 GB: instant to create, real bytes to hash. The
        // hash loop observes cancellation per 1 MB chunk, so the
        // cancel must land in milliseconds, not at end-of-file.
        string dir = Path.Combine(Path.GetTempPath(), "sentinel-big-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        string big = Path.Combine(dir, "big.bin");
        Skip.IfNot(TryCreateSparseFile(big, 2L * 1024 * 1024 * 1024),
            "NTFS sparse files unavailable in this environment.");

        string dbPath = Path.Combine(Path.GetTempPath(), "sentinel-big-" + Guid.NewGuid().ToString("N") + ".db");
        try
        {
            using var db = new Sentinel.Store.SentinelDb(dbPath);
            var orchestrator = new ScanOrchestrator(
                db,
                idle: new FixedIdleProbe(TimeSpan.FromMinutes(30)),
                fullscreen: new FixedFullscreenProbe(false),
                battery: new FixedBatteryProbe(PowerState.AcPower));
            using var cts = new CancellationTokenSource();

            var run = orchestrator.RunAsync(
                new ScanOptions(ScanMode.Turbo, [dir]), new PauseToken(), cts.Token);
            await Task.Delay(300);
            Assert.False(run.IsCompleted); // Still hashing the 2 GB file.

            var sw = Stopwatch.StartNew();
            cts.Cancel();
            var result = await AwaitGuarded(run);
            sw.Stop();

            Assert.Equal(ScanOutcome.Cancelled, result.Outcome);
            Assert.True(sw.ElapsedMilliseconds < 1000,
                $"Cancel must land within 1s on a multi-GB file; took {sw.ElapsedMilliseconds}ms.");
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
            foreach (var suffix in new[] { "", "-wal", "-shm" })
            {
                try { File.Delete(dbPath + suffix); } catch { }
            }
        }
    }

    [Fact]
    public async Task PauseToken_Blocks_And_Releases()
    {
        var token = new PauseToken();
        token.Pause();
        Assert.True(token.IsPaused);

        var wait = token.WaitIfPausedAsync(CancellationToken.None);
        await Task.Delay(100);
        Assert.False(wait.IsCompleted);

        token.Resume();
        Assert.False(token.IsPaused);
        await AwaitGuarded(wait);
    }

    private static async Task<T> AwaitGuarded<T>(Task<T> task)
    {
        var done = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(30)));
        Assert.Same(task, done);
        return await task;
    }

    private static async Task AwaitGuarded(Task task)
    {
        var done = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(30)));
        Assert.Same(task, done);
        await task;
    }

    private const uint FsctlSetSparse = 0x900C4;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    private static bool TryCreateSparseFile(string path, long length)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None);
            bool sparse = DeviceIoControl(
                stream.SafeFileHandle, FsctlSetSparse,
                IntPtr.Zero, 0, IntPtr.Zero, 0,
                out _, IntPtr.Zero);
            if (!sparse)
            {
                stream.Dispose();
                File.Delete(path);
                return false;
            }

            stream.SetLength(length);
            return true;
        }
        catch
        {
            try { File.Delete(path); } catch { }
            return false;
        }
    }
}
