using System.Diagnostics;
using Sentinel.Engine.Agent;
using Sentinel.Engine.Scan;
using Xunit;
using Xunit.Abstractions;

namespace Sentinel.Tests;

// A10 performance leg (03 §5, 05 §6). These tests are OPT-IN via
// SENTINEL_PERF=1 and SKIP otherwise with an explicit reason — they
// take ~10 minutes and need a quiet box. Run them alone:
//
//   set SENTINEL_PERF=1
//   dotnet test tests/Sentinel.Tests -c Release --filter FullyQualifiedName~ScanPerfTests
//
// CPU% is measured per-second on this process and reduced to a
// rolling-30-second maximum (the acceptance methodology); RAM is the
// peak working-set DELTA over the pre-scan baseline; throughput
// comes from the preview hub (cancelled scans roll back, so result
// counts would read zero). Knobs: SENTINEL_PERF_FILES (default
// 40000), SENTINEL_PERF_FILE_KB (default 64), SENTINEL_PERF_SECONDS
// (default 40), SENTINEL_PERF_FIXDIR (reuse one fixture dir across
// split runs instead of regenerating per process).
public sealed class ScanPerfTests : IClassFixture<ScanPerfTests.PerfFixture>
{
    private readonly PerfFixture _fixture;
    private readonly ITestOutputHelper _output;

    public ScanPerfTests(PerfFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _output = output;
    }

    private static bool PerfEnabled =>
        string.Equals(Environment.GetEnvironmentVariable("SENTINEL_PERF"), "1", StringComparison.Ordinal);

    private static int PerfSeconds =>
        int.TryParse(Environment.GetEnvironmentVariable("SENTINEL_PERF_SECONDS"), out int s) && s >= 10 ? s : 40;

    public sealed class PerfFixture : IDisposable
    {
        private readonly bool _ownsDir;

        public string Root { get; }

        public int FileCount { get; }

        public PerfFixture()
        {
            // Fixture builds even when perf is off (IClassFixture
            // always constructs) — but stays cheap: the heavy file
            // generation only runs when SENTINEL_PERF=1.
            int files = int.TryParse(Environment.GetEnvironmentVariable("SENTINEL_PERF_FILES"), out int f) && f > 0 ? f : 40000;
            int kb = int.TryParse(Environment.GetEnvironmentVariable("SENTINEL_PERF_FILE_KB"), out int k) && k > 0 ? k : 64;
            string? fixDir = Environment.GetEnvironmentVariable("SENTINEL_PERF_FIXDIR");
            if (!PerfEnabled || string.IsNullOrWhiteSpace(fixDir))
            {
                Root = Path.Combine(Path.GetTempPath(), "sentinel-perf-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(Root);
                _ownsDir = true;
                FileCount = 0;
                if (!PerfEnabled)
                {
                    return;
                }

                Generate(Root, files, kb);
                FileCount = files;
                return;
            }

            // Reusable fixture: split guest runs share one directory
            // (each test still uses a FRESH database, so every file
            // hashes every run). The marker pins the file count — a
            // different SENTINEL_PERF_FILES regenerates. Guest file
            // generation varies wildly run to run (observed 2–9 min
            // for 10k files); regenerating per split run would both
            // waste the leg and risk the guestcontrol timeout.
            string marker = Path.Combine(fixDir, $"fixture-{files}x{kb}.ready");
            if (File.Exists(marker) && Directory.Exists(fixDir))
            {
                Root = fixDir;
                FileCount = files;
                _ownsDir = false;
                return;
            }

            Directory.CreateDirectory(fixDir);
            Generate(fixDir, files, kb);
            File.WriteAllText(marker, "ready");
            Root = fixDir;
            FileCount = files;
            _ownsDir = false;
        }

        private static void Generate(string dir, int files, int kb)
        {
            var buffer = new byte[kb * 1024];
            new Random(99).NextBytes(buffer);
            for (int i = 0; i < files; i++)
            {
                // Stamp the index in so files differ.
                BitConverter.GetBytes(i).CopyTo(buffer, 0);
                File.WriteAllBytes(Path.Combine(dir, $"d{i:D5}.bin"), buffer);
            }
        }

        public void Dispose()
        {
            // A reused fixture survives for the next split run; the
            // leg cleans it at the end (or it stays as replayable
            // evidence of what was measured).
            if (!_ownsDir)
            {
                return;
            }

            try { Directory.Delete(Root, recursive: true); } catch { }
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

    // Dedicated sampler thread: under full saturation the pool
    // starves PeriodicTimer continuations (first A10 guest run lost
    // 4 of 32 ticks on the cap-25 burner). A sleeping thread always
    // gets its slice. The Process instance lives on this thread
    // only — Process is not thread-safe.
    private sealed class CpuSampler : IDisposable
    {
        private readonly Thread _thread;
        private readonly List<double> _cpuPercent = new();
        private readonly List<long> _workingSet = new();
        private readonly List<double> _intervalsMs = new();
        private readonly List<double> _guestTotal = new();
        private readonly ManualResetEventSlim _stop = new(false);
        private readonly int _cores = Environment.ProcessorCount;

        public CpuSampler()
        {
            _thread = new Thread(SampleLoop) { IsBackground = true, Name = "A10CpuSampler" };
            _thread.Start();
        }

        public IReadOnlyList<double> CpuPercent
        {
            get { lock (_cpuPercent) { return _cpuPercent.ToList(); } }
        }

        public IReadOnlyList<long> WorkingSet
        {
            get { lock (_workingSet) { return _workingSet.ToList(); } }
        }

        // Validity signal: the sampler asked for 1s ticks. Avg >>1s
        // means the VM/host was too saturated to schedule even a
        // sleeping thread — the % numbers from that span are
        // starvation-limited, not governor-limited.
        public (double AvgMs, double MaxMs) TickIntervals
        {
            get
            {
                lock (_cpuPercent)
                {
                    return _intervalsMs.Count == 0
                        ? (0, 0)
                        : (_intervalsMs.Average(), _intervalsMs.Max());
                }
            }
        }

        // Whole-guest CPU% per tick (all processes). Disambiguates
        // "governor parked us" (guest idle, we low) from "someone
        // else ate the box" (guest busy, we low).
        public IReadOnlyList<double> GuestTotal
        {
            get { lock (_cpuPercent) { return _guestTotal.ToList(); } }
        }

        public Task StopAsync()
        {
            Dispose();
            return Task.CompletedTask;
        }

        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 1)
            {
                return;
            }

            _stop.Set();
            _thread.Join(TimeSpan.FromSeconds(5));
            _stop.Dispose();
        }

        private void SampleLoop()
        {
            using var proc = Process.GetCurrentProcess();
            proc.Refresh();
            var prevCpu = proc.TotalProcessorTime;
            long prevWall = Stopwatch.GetTimestamp();
            var prevAll = SnapshotAllCpu();
            // The snapshot itself costs ~100ms+ in a stressed guest;
            // a fixed 1s wait would stretch ticks to ~1.14s and lose
            // samples (gov4: 29 of 32). Debit the previous iteration's
            // work from the wait instead. % math already normalizes
            // by actual wall time, so this only restores cadence.
            long prevWorkMs = 0;
            while (!_stop.Wait(TimeSpan.FromMilliseconds(Math.Max(50, 1000 - prevWorkMs))))
            {
                long workStart = Stopwatch.GetTimestamp();
                proc.Refresh();
                var cpu = proc.TotalProcessorTime;
                long wall = Stopwatch.GetTimestamp();
                double wallMs = (wall - prevWall) * 1000.0 / Stopwatch.Frequency;
                double pct = wallMs > 0
                    ? (cpu - prevCpu).TotalMilliseconds / (wallMs * _cores) * 100.0
                    : 0;
                prevCpu = cpu;
                prevWall = wall;
                var all = SnapshotAllCpu();
                double guestMs = 0;
                foreach (var kv in all)
                {
                    if (prevAll.TryGetValue(kv.Key, out double before))
                    {
                        guestMs += Math.Max(0, kv.Value - before);
                    }
                }

                prevAll = all;
                double guestPct = wallMs > 0 ? guestMs / (wallMs * _cores) * 100.0 : 0;
                lock (_cpuPercent)
                {
                    _cpuPercent.Add(pct);
                    _workingSet.Add(proc.WorkingSet64);
                    _intervalsMs.Add(wallMs);
                    _guestTotal.Add(guestPct);
                }

                prevWorkMs = (Stopwatch.GetTimestamp() - workStart) * 1000 / Stopwatch.Frequency;
            }
        }

        private static Dictionary<int, double> SnapshotAllCpu()
        {
            var snap = new Dictionary<int, double>();
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    snap[p.Id] = p.TotalProcessorTime.TotalMilliseconds;
                }
                catch
                {
                    // Exited or unreadable mid-snapshot: skip it.
                }
                finally
                {
                    p.Dispose();
                }
            }

            return snap;
        }
    }

    // Rolling-30-second maximum over FULL windows only. Partial
    // leading windows (a 1-sample "average" of a startup burst) are
    // not 30-second averages and must not set the max — the first
    // A10 guest run proved that artifact (Bal10: mean 6.3%, fake
    // "rolling" max 27.6% from sample #1). NaN when the span never
    // filled one window: callers fail LOUD, never pass vacuously.
    private static double MaxFullWindowMean(IReadOnlyList<double> samples, int window)
    {
        if (samples.Count < window)
        {
            return double.NaN;
        }

        double max = 0;
        for (int end = window; end <= samples.Count; end++)
        {
            double sum = 0;
            for (int i = end - window; i < end; i++)
            {
                sum += samples[i];
            }

            max = Math.Max(max, sum / window);
        }

        return max;
    }

    [SkippableFact]
    public async Task Perf_Governor_Holds_All_Caps()
    {
        Skip.IfNot(PerfEnabled, "Perf leg is opt-in: set SENTINEL_PERF=1 (see a10-perf.md).");
        Assert.True(_fixture.FileCount > 0, "Perf fixture did not generate.");

        // NO unpaced warm-up/baseline: on NEM-backed VirtualBox an
        // unpaced all-core spin intermittently wedges the vCPUs for
        // minutes at a time (gov5: >10min silence in a 1s phase).
        // Starvation is detected per-cap instead via tick/guest
        // brackets (a starved run shows collapsed ticks or a guest
        // far busier than the process — judge the line, not just
        // the assert).
        foreach (int cap in new[] { 15, 25, 30, 60 })
        {
            var governor = new CpuGovernor(capPercent: cap);
            var (samples, avgTickMs, maxTickMs, guestAvg) = await BurnSampledAsync(governor, seconds: 32);
            double mean = samples.Count == 0 ? 0 : samples.Average();
            double maxRolling = MaxFullWindowMean(samples, window: 30);
            _output.WriteLine($"governor cap={cap}: samples={samples.Count} mean={mean:F1}% maxRolling30={(double.IsNaN(maxRolling) ? "N/A" : maxRolling.ToString("F1") + "%")} tickAvg={avgTickMs:F0}ms tickMax={maxTickMs:F0}ms guestAvg={guestAvg:F1}%");
            _output.WriteLine("series: " + string.Join(" ", samples.Select(s => s.ToString("F1"))));
            Assert.True(samples.Count >= 30,
                $"Governor cap {cap}: only {samples.Count} samples — sampling shortfall, re-run.");
            Assert.True(maxRolling < cap + 5,
                $"Governor failed at cap {cap}: rolling-30s max {maxRolling:F1}% (mean {mean:F1}%).");
        }
    }

    [SkippableFact]
    public async Task Perf_FullScan_Eco15()
    {
        await RunModePerfAsync("Eco15", new ScanOptions(ScanMode.Eco, [_fixture.Root]), capPercent: 15);
    }

    [SkippableFact]
    public async Task Perf_FullScan_Balanced10()
    {
        await RunModePerfAsync("Bal10", new ScanOptions(ScanMode.Balanced, [_fixture.Root], balancedCapPercent: 10), capPercent: 10);
    }

    [SkippableFact]
    public async Task Perf_FullScan_Balanced25()
    {
        await RunModePerfAsync("Bal25", new ScanOptions(ScanMode.Balanced, [_fixture.Root]), capPercent: 25);
    }

    [SkippableFact]
    public async Task Perf_FullScan_Balanced30()
    {
        await RunModePerfAsync("Bal30", new ScanOptions(ScanMode.Balanced, [_fixture.Root], balancedCapPercent: 30), capPercent: 30);
    }

    [SkippableFact]
    public async Task Perf_FullScan_Turbo60()
    {
        await RunModePerfAsync("Turbo60", new ScanOptions(ScanMode.Turbo, [_fixture.Root]), capPercent: 60);
    }

    private async Task RunModePerfAsync(string label, ScanOptions options, int capPercent)
    {
        Skip.IfNot(PerfEnabled, "Perf leg is opt-in: set SENTINEL_PERF=1 (see a10-perf.md).");
        Assert.True(_fixture.FileCount > 0, "Perf fixture did not generate.");

        // Fresh DB per mode: a second run over the same store would
        // skip every file as unchanged and measure nothing.
        string dbPath = Path.Combine(Path.GetTempPath(), "sentinel-perf-" + Guid.NewGuid().ToString("N") + ".db");
        try
        {
            using var db = new Sentinel.Store.SentinelDb(dbPath);
            var orchestrator = new ScanOrchestrator(
                db,
                idle: new FixedIdleProbe(TimeSpan.FromMinutes(30)),
                fullscreen: new FixedFullscreenProbe(false),
                battery: new FixedBatteryProbe(PowerState.AcPower));
            var hub = new EvidencePreviewHub();

            long ramBaseline;
            using (var self = Process.GetCurrentProcess())
            {
                ramBaseline = self.WorkingSet64;
            }

            using var sampler = new CpuSampler();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(PerfSeconds));
            var sw = Stopwatch.StartNew();
            var result = await orchestrator.RunAsync(options, new PauseToken(), cts.Token, hub);
            sw.Stop();
            await sampler.StopAsync();

            var samples = sampler.CpuPercent;
            double maxRolling = MaxFullWindowMean(samples, window: 30);
            double mean = samples.Count == 0 ? 0 : samples.Average();
            long peakRam = sampler.WorkingSet.Count == 0 ? ramBaseline : sampler.WorkingSet.Max();
            long ramDeltaMb = Math.Max(0, peakRam - ramBaseline) / (1024 * 1024);

            var snap = hub.Snapshot();
            long bytes = snap.Files.Sum(f => f.Size);
            double seconds = Math.Max(1, sw.Elapsed.TotalSeconds);
            double filesPerSec = snap.Files.Count / seconds;
            double mbPerSec = bytes / (1024.0 * 1024.0) / seconds;

            var (avgTickMs, maxTickMs) = sampler.TickIntervals;
            var guest = sampler.GuestTotal;
            double guestAvg = guest.Count == 0 ? 0 : guest.Average();
            _output.WriteLine(
                $"{label}: outcome={result.Outcome} span={sw.Elapsed.TotalSeconds:F0}s samples={samples.Count} " +
                $"cpuMean={mean:F1}% cpuMaxRolling30={(double.IsNaN(maxRolling) ? "N/A" : maxRolling.ToString("F1") + "%")} (cap {capPercent}) " +
                $"tickAvg={avgTickMs:F0}ms tickMax={maxTickMs:F0}ms guestAvg={guestAvg:F1}% " +
                $"ramBaseline={ramBaseline / (1024 * 1024)}MB ramPeakDelta={ramDeltaMb}MB " +
                $"files={snap.Files.Count} ({filesPerSec:F0}/s) bytes={bytes / (1024 * 1024)}MB ({mbPerSec:F1}MB/s)");

            Assert.True(samples.Count >= 30,
                $"{label}: only {samples.Count} samples — the span never filled a 30s window, raise SENTINEL_PERF_FILES.");
            Assert.True(maxRolling < capPercent + 5,
                $"{label}: rolling-30s CPU max {maxRolling:F1}% exceeds cap {capPercent} (+5pp slack).");
            Assert.True(ramDeltaMb < 250,
                $"{label}: peak working-set delta {ramDeltaMb}MB exceeds the 250MB bound.");
        }
        finally
        {
            foreach (var suffix in new[] { "", "-wal", "-shm" })
            {
                try { File.Delete(dbPath + suffix); } catch { }
            }
        }
    }

    private static async Task<(List<double> Samples, double AvgTickMs, double MaxTickMs, double GuestAvg)> BurnSampledAsync(CpuGovernor paced, int seconds)
    {
        int threads = Environment.ProcessorCount;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));
        var burners = new Task<double>[threads];
        for (int i = 0; i < burners.Length; i++)
        {
            burners[i] = Task.Run(async () =>
            {
                double x = 1;
                try
                {
                    while (true)
                    {
                        cts.Token.ThrowIfCancellationRequested();
                        var end = DateTime.UtcNow.AddMilliseconds(20);
                        while (DateTime.UtcNow < end)
                        {
                            x += Math.Sqrt(x);
                        }

                        await paced.PaceAsync(cts.Token);
                    }
                }
                catch (OperationCanceledException)
                {
                    // Expected shutdown at the end of the measurement window.
                }

                return x;
            });
        }

        using var sampler = new CpuSampler();
        await Task.WhenAll(burners);
        await sampler.StopAsync();
        var (avgTickMs, maxTickMs) = sampler.TickIntervals;
        var guest = sampler.GuestTotal;
        double guestAvg = guest.Count == 0 ? 0 : guest.Average();
        return (sampler.CpuPercent.ToList(), avgTickMs, maxTickMs, guestAvg);
    }
}
