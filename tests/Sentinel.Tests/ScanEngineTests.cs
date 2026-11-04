using System.Diagnostics;
using Sentinel.Engine.Scan;
using Xunit;

namespace Sentinel.Tests;

public sealed class ScanEngineTests : IDisposable
{
    private readonly string _root;
    private readonly string _dbPath;
    private string? _plantExePath;
    private bool _disposed;

    public ScanEngineTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "sentinel-scan-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
        var payload = new byte[4096];
        new Random(42).NextBytes(payload);
        for (int i = 0; i < 20; i++)
        {
            File.WriteAllBytes(Path.Combine(_root, $"f{i:D3}.bin"), payload);
        }

        _dbPath = Path.Combine(Path.GetTempPath(), "sentinel-scan-" + Guid.NewGuid().ToString("N") + ".db");
    }

    [Fact]
    public async Task Queue_Drains_Priority_First()
    {
        using var queue = new PriorityWorkQueue<string>();
        await queue.EnqueueBulkAsync("b1", CancellationToken.None);
        await queue.EnqueueBulkAsync("b2", CancellationToken.None);
        await queue.EnqueuePriorityAsync("p1", CancellationToken.None);
        await queue.EnqueuePriorityAsync("p2", CancellationToken.None);
        queue.Complete();

        var order = new List<string>();
        while (queue.TryDequeue(out var item))
        {
            order.Add(item);
        }

        Assert.Equal(["p1", "p2", "b1", "b2"], order);
        Assert.True(queue.IsCompleted);
    }

    [Fact]
    public async Task Queue_Blocks_Producers_At_Bound()
    {
        using var queue = new PriorityWorkQueue<string>(bound: 2);
        var ct = CancellationToken.None;
        await queue.EnqueueBulkAsync("b1", ct);
        await queue.EnqueueBulkAsync("b2", ct);

        var third = queue.EnqueueBulkAsync("b3", ct);
        Assert.False(third.IsCompleted); // Full: producer must wait, not buffer.

        Assert.True(queue.TryDequeue(out _));
        await third; // A dequeue frees exactly one slot.
        Assert.Equal(2, queue.Count);
    }

    // R5: live insertion lands ahead of bulk, is accepted during
    // the post-enumeration drain (the long phase), and is refused
    // only once fully drained — never stranded, never silent.
    [Fact]
    public async Task LiveInsert_JumpsBulk_AcceptedDuringDrain_RefusedWhenDrained()
    {
        using var queue = new PriorityWorkQueue<string>();
        var ct = CancellationToken.None;
        await queue.EnqueueBulkAsync("b1", ct);
        await queue.EnqueueBulkAsync("b2", ct);

        Assert.True(queue.TryEnqueuePriorityLive("p-live"));
        queue.Complete();
        Assert.True(queue.TryEnqueuePriorityLive("p-drain")); // drain ongoing: accepted.

        var order = new List<string>();
        while (queue.TryDequeue(out var item))
        {
            order.Add(item);
        }

        Assert.Equal(["p-live", "p-drain", "b1", "b2"], order);
        Assert.True(queue.IsCompleted);
        Assert.False(queue.TryEnqueuePriorityLive("p-late")); // drained: refused.
    }

    // R5: a full queue refuses live insertion WITHOUT blocking —
    // the caller falls back to delta rescan instead of wedging.
    [Fact]
    public async Task LiveInsert_FullQueue_Refuses_WithoutBlocking()
    {
        using var queue = new PriorityWorkQueue<string>(bound: 1);
        var ct = CancellationToken.None;
        await queue.EnqueueBulkAsync("b1", ct);

        var sw = Stopwatch.StartNew();
        Assert.False(queue.TryEnqueuePriorityLive("p"));
        sw.Stop();
        Assert.True(sw.ElapsedMilliseconds < 1000); // never blocks.

        Assert.True(queue.TryDequeue(out _));
        Assert.True(queue.TryEnqueuePriorityLive("p")); // slot freed: accepted.
    }

    // R5: no scan running, no live queue — false, not an exception.
    [Fact]
    public void LiveInsert_WithoutScan_ReturnsFalse()
    {
        using var db = new Sentinel.Store.SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(db);

        Assert.False(orchestrator.IsScanActive);
        Assert.False(orchestrator.TryEnqueuePriorityLive(@"C:\nope.exe"));
    }

    // R5: an exited/unknown pid is a verdict, not an error.
    [Fact]
    public void ProcessCheck_UnknownPid_IsHonest_NotThrow()
    {
        var verdict = Sentinel.Engine.SystemInventory.PriorityProcessCheck.Check(int.MaxValue);

        Assert.Equal("NotFound", verdict.Verdict);
        Assert.Null(verdict.Sha256);
        Assert.True(verdict.ElapsedMs >= 0);
    }

    // R5 (04 Phase 2): a new process planted MID-SCAN is
    // priority-checked and the verdict is timed. Plant = a real
    // benign sleeper (timeout.exe /t 30), read-only inspected,
    // always killed. Its exe path is live-inserted into the
    // RUNNING scan and must land in the SAME generation (delta
    // rescan would stamp a new one — this proves insertion).
    [SkippableFact]
    public async Task Watcher_PlantedProcess_PriorityChecked_VerdictTimed()
    {
        string big = Path.Combine(_root, "big");
        Directory.CreateDirectory(big);
        var payload = new byte[64 * 1024];
        new Random(7).NextBytes(payload);
        for (int i = 0; i < 200; i++)
        {
            File.WriteAllBytes(Path.Combine(big, $"w{i:D4}.bin"), payload);
        }

        using var db = new Sentinel.Store.SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(db);
        var pause = new PauseToken();
        var scanTask = orchestrator.RunAsync(
            new ScanOptions(ScanMode.Turbo, [_root]), pause);

        bool sawActive = false;
        for (int i = 0; i < 200 && !scanTask.IsCompleted; i++)
        {
            if (orchestrator.IsScanActive)
            {
                sawActive = true;
                break;
            }

            await Task.Delay(50);
        }

        Skip.IfNot(sawActive, "Scan drained before the plant — host too fast to prove mid-scan insertion.");

        // Hold the drain open: pausing freezes workers on the live
        // queue (still mid-scan: started, active, undrained), so the
        // plant+verdict+insert window is deterministic, not a race
        // against a ~1s drain. A refusal below still means the drain
        // genuinely won → honest skip, never a false pass.
        pause.Pause();

        Process? plant = null;
        try
        {
            try
            {
                // ping.exe, not timeout.exe: timeout exits instantly without a
                // console ("Input redirection is not supported"), which made
                // this test a coin flip under automation. ping never reads
                // stdin, is Microsoft-signed (same verdict assertions), and
                // is always killed in the finally below.
                plant = Process.Start(new ProcessStartInfo
                {
                    FileName = Path.Combine(Environment.SystemDirectory, "ping.exe"),
                    Arguments = "-n 30 127.0.0.1",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                });
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or FileNotFoundException)
            {
                Skip.If(true, "ping.exe unavailable on this host — no benign plant to check.");
                return;
            }

            Skip.If(plant is null || plant.HasExited, "Plant exited before the check — nothing to verify.");

            var verdict = Sentinel.Engine.SystemInventory.PriorityProcessCheck.Check(plant.Id);
            string diag = $"pid={plant.Id} alive={!plant.HasExited} " +
                $"verdict={verdict.Verdict} detail={verdict.Detail} elapsedMs={verdict.ElapsedMs}";

            Assert.False(string.IsNullOrWhiteSpace(verdict.ExePath), diag);
            Assert.Equal("SignedPublisher", verdict.Verdict);
            Assert.False(string.IsNullOrWhiteSpace(verdict.Sha256));
            // Timed (03 §5 target < 3s; hard bound 10s pins the O(1)
            // no-enumeration, no-network-revocation properties).
            Assert.True(verdict.ElapsedMs < 10_000,
                $"Verdict took {verdict.ElapsedMs}ms — priority path must stay fast.");

            // The verdict's OWN exe string does insert + lookup: no
            // assumption about MainModule path normalization.
            _plantExePath = verdict.ExePath!;
            bool inserted = orchestrator.TryEnqueuePriorityLive(_plantExePath);
            if (!inserted)
            {
                // The drain genuinely finished under pause (nearly
                // impossible with 220 files, but load is load).
                Skip.If(true, "Scan drained under pause before the insert — host too fast.");
                return;
            }
        }
        finally
        {
            pause.Resume(); // Always: a held pause must never wedge the scan.
            try
            {
                if (plant is not null && !plant.HasExited)
                {
                    plant.Kill();
                    plant.WaitForExit(5000);
                }

                plant?.Dispose();
            }
            catch
            {
                // Best-effort cleanup; the sleeper exits on its own in ≤30s.
            }
        }

        var result = await scanTask;
        Assert.Equal(ScanOutcome.Completed, result.Outcome);
        Assert.True(result.FilesSeen >= 200);

        var plantFp = db.GetFingerprint(_plantExePath!);
        Assert.NotNull(plantFp); // Inventoried by the live insert...
        Assert.Equal(result.Generation, plantFp.LastSeenGeneration); // ...in THIS run.
        Assert.False(orchestrator.IsScanActive);
        Assert.False(orchestrator.TryEnqueuePriorityLive(@"C:\late.exe"));
    }

    [Fact]
    public void Snooze_Suppresses_Identical_Evidence_Only()
    {
        var tracker = new SnoozeTracker();
        var now = DateTime.UtcNow;
        var cooldown = TimeSpan.FromDays(7);

        Assert.True(tracker.ShouldEmit("cache-x", "hash1", cooldown, now));
        Assert.False(tracker.ShouldEmit("cache-x", "hash1", cooldown, now.AddHours(1)));
        Assert.True(tracker.ShouldEmit("cache-x", "hash2", cooldown, now.AddHours(2)));
        Assert.True(tracker.ShouldEmit("cache-x", "hash2", cooldown, now.AddDays(8)));
        Assert.True(tracker.ShouldEmit("other", "hash1", cooldown, now));
    }

    [Fact]
    public void Options_Rejects_BalancedCap_Outside_10_To_30()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new ScanOptions(ScanMode.Balanced, ["."], balancedCapPercent: 9));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new ScanOptions(ScanMode.Balanced, ["."], balancedCapPercent: 31));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new ScanOptions(ScanMode.Balanced, ["."], balancedCapPercent: 60));

        var ok = new ScanOptions(ScanMode.Balanced, ["."], balancedCapPercent: 30);
        Assert.Equal(30, ok.CpuCapPercent);
        Assert.Equal(15, new ScanOptions(ScanMode.Eco, ["."]).CpuCapPercent);
        Assert.Equal(60, new ScanOptions(ScanMode.Turbo, ["."]).CpuCapPercent);
    }

    [Fact]
    public async Task Eco_Refuses_When_User_Active()
    {
        using var db = new Sentinel.Store.SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(
            db,
            idle: new FixedIdleProbe(TimeSpan.FromSeconds(30)),
            fullscreen: new FixedFullscreenProbe(false));

        var result = await orchestrator.RunAsync(
            new ScanOptions(ScanMode.Eco, [_root]), new PauseToken());

        Assert.Equal(ScanOutcome.RefusedNotIdle, result.Outcome);
        Assert.Equal(0, result.FilesSeen);
    }

    [Fact]
    public async Task Eco_Refuses_When_Fullscreen()
    {
        using var db = new Sentinel.Store.SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(
            db,
            idle: new FixedIdleProbe(TimeSpan.FromMinutes(30)),
            fullscreen: new FixedFullscreenProbe(true));

        var result = await orchestrator.RunAsync(
            new ScanOptions(ScanMode.Eco, [_root]), new PauseToken());

        Assert.Equal(ScanOutcome.RefusedFullscreen, result.Outcome);
    }

    [Fact]
    public async Task Generations_Increment_And_Delta_Touches_Subset()
    {
        using var db = new Sentinel.Store.SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(
            db,
            idle: new FixedIdleProbe(TimeSpan.FromMinutes(30)),
            fullscreen: new FixedFullscreenProbe(false));
        var options = new ScanOptions(ScanMode.Balanced, [_root]);

        var first = await orchestrator.RunAsync(options, new PauseToken());
        var second = await orchestrator.RunAsync(options, new PauseToken());

        Assert.Equal(ScanOutcome.Completed, first.Outcome);
        Assert.Equal(1, first.Generation);
        Assert.Equal(20, first.FilesHashed);
        Assert.Equal(2, second.Generation);
        Assert.Equal(0, second.FilesHashed); // Incremental: nothing rehashed.

        File.WriteAllBytes(Path.Combine(_root, "f000.bin"), new byte[8192]);
        var delta = await orchestrator.RescanPathsAsync(
            [Path.Combine(_root, "f000.bin")], options, new PauseToken());

        Assert.Equal(3, delta.Generation);
        Assert.Equal(1, delta.FilesSeen);
        Assert.Equal(1, delta.FilesHashed);
    }

    [Fact]
    public async Task Cancel_MidScan_Records_Cancelled_Row()
    {
        using var db = new Sentinel.Store.SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(
            db,
            idle: new FixedIdleProbe(TimeSpan.FromMinutes(30)),
            fullscreen: new FixedFullscreenProbe(false));
        var pause = new PauseToken();
        pause.Pause(); // Workers block before touching file #1: deterministic.
        using var cts = new CancellationTokenSource();
        var task = orchestrator.RunAsync(
            new ScanOptions(ScanMode.Balanced, [_root]), pause, cts.Token);
        await Task.Delay(300, CancellationToken.None);
        cts.Cancel();

        var result = await task;

        Assert.Equal(ScanOutcome.Cancelled, result.Outcome);
        Assert.Equal(1, result.Generation);
        var run = db.GetRun(1);
        Assert.NotNull(run);
        Assert.Equal("Cancelled", run.Status);
        Assert.Equal(0, run.FilesSeen);
    }

    [Fact]
    public async Task Pause_And_Resume_Completes()
    {
        using var db = new Sentinel.Store.SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(
            db,
            idle: new FixedIdleProbe(TimeSpan.FromMinutes(30)),
            fullscreen: new FixedFullscreenProbe(false));
        var pause = new PauseToken();
        pause.Pause();
        var task = orchestrator.RunAsync(
            new ScanOptions(ScanMode.Balanced, [_root]), pause);
        await Task.Delay(300);
        Assert.False(task.IsCompleted);
        pause.Resume();

        var result = await task;

        Assert.Equal(ScanOutcome.Completed, result.Outcome);
        Assert.Equal(20, result.FilesSeen);
    }

    [Fact]
    public async Task Cancel_Stops_Scan()
    {
        using var db = new Sentinel.Store.SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(
            db,
            idle: new FixedIdleProbe(TimeSpan.FromMinutes(30)),
            fullscreen: new FixedFullscreenProbe(false));
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var result = await orchestrator.RunAsync(
            new ScanOptions(ScanMode.Balanced, [_root]), new PauseToken(), cts.Token);

        Assert.Equal(ScanOutcome.Cancelled, result.Outcome);
    }

    // Exact pacing math on a fake clock: 4 cores, cap 25.
    // Quantum 500ms wall + 1000ms CPU = 50% usage -> allowed wall is
    // Per-period absolute cap (P1-05): 4 cores, cap 25 → 250ms
    // allowed per 250ms period. After 100ms wall / 400ms CPU the
    // burn-down schedule allows 100, overrun is 300, and the call
    // sleeps its per-core share: 300/4 = 75ms.
    [Fact]
    public async Task Governor_Math_Sleeps_Share_Of_Period_Overrun()
    {
        var clock = new FakeClock(cores: 4);
        var governor = new CpuGovernor(capPercent: 25, clock);

        clock.Advance(wallMs: 100, cpuMs: 400);
        var sw = Stopwatch.StartNew();
        await governor.PaceAsync(CancellationToken.None);
        sw.Stop();
        Assert.True(sw.ElapsedMilliseconds >= 50,
            $"Overrun call must sleep ~75ms, slept {sw.ElapsedMilliseconds}ms.");
    }

    [Fact]
    public async Task Governor_Math_Under_Allowance_Does_Not_Sleep()
    {
        var clock = new FakeClock(cores: 4);
        var governor = new CpuGovernor(capPercent: 25, clock);

        clock.Advance(wallMs: 100, cpuMs: 20); // 5% usage.
        var sw = Stopwatch.StartNew();
        await governor.PaceAsync(CancellationToken.None);
        sw.Stop();
        Assert.True(sw.ElapsedMilliseconds < 100,
            "Under-allowance call must not sleep.");
    }

    [Fact]
    public async Task Governor_Math_Period_Roll_Carries_No_Debt()
    {
        var clock = new FakeClock(cores: 4);
        var governor = new CpuGovernor(capPercent: 25, clock);

        // A huge overrun followed by a period roll: the new period
        // starts clean (absolute per-period cap, no carried debt).
        clock.Advance(wallMs: 300, cpuMs: 4000);
        var sw = Stopwatch.StartNew();
        await governor.PaceAsync(CancellationToken.None);
        sw.Stop();
        Assert.True(sw.ElapsedMilliseconds < 100,
            "Post-roll call must not pay the previous period's overrun.");
    }

    // 1-core exactness (P1-05): 1 core, cap 20 → 50ms per period.
    // After 200ms wall / 200ms CPU the schedule allows 40, overrun
    // is 160, and the single caller sleeps all of it.
    [Fact]
    public async Task Governor_Math_One_Core_Sleeps_Full_Overrun()
    {
        var clock = new FakeClock(cores: 1);
        var governor = new CpuGovernor(capPercent: 20, clock);

        clock.Advance(wallMs: 200, cpuMs: 200);
        var sw = Stopwatch.StartNew();
        await governor.PaceAsync(CancellationToken.None);
        sw.Stop();
        Assert.True(sw.ElapsedMilliseconds >= 120,
            $"1-core overrun must sleep ~160ms, slept {sw.ElapsedMilliseconds}ms.");
    }

    // Live budget test (03 §5), self-calibrating: the same burners run
    // unpaced (baseline) then paced, so the test cannot pass on a fast
    // machine by luck; it skips honestly when the host is too busy
    // to establish an unpaced baseline.
    [SkippableFact]
    public async Task Governor_Holds_Process_Under_Cap()
    {
        await BurnAsync(paced: null, seconds: 1); // Warm-up: settle JIT + turbo.
        double baseline = await BurnAsync(paced: null, seconds: 2);
        Skip.IfNot(baseline > 40.0,
            $"Host too busy to prove throttling (unpaced baseline {baseline:F1}%).");
        var governor = new CpuGovernor(capPercent: 20);
        double paced = await BurnAsync(governor, seconds: 3);

        // Stability re-check: if the host cannot reproduce its own
        // baseline (load arrived mid-test), neither assert below is
        // meaningful. A broken governor still fails: paced ~= baseline
        // reproduces fine, and the asserts catch it.
        double verify = await BurnAsync(paced: null, seconds: 1);
        Skip.IfNot(verify > baseline * 0.7,
            $"Host shifted mid-test (baseline {baseline:F1}% vs verify {verify:F1}%) — throttling unprovable.");

        Assert.True(paced < baseline * 0.6,
            $"Governor failed: paced {paced:F1}% vs unpaced baseline {baseline:F1}%.");
        // Cap 20 + 5pp slack for burn-chunk overshoot (one ~20ms
        // chunk per thread can land inside a period after the
        // allowance is spent) and sampling noise. The old 35.0
        // gate permitted 1.75x the cap and hid the (unpaced+cap)/2
        // fixed point (P1-05).
        Assert.True(paced < 25.0, $"Governor failed: paced average {paced:F1}% against cap 20.");
    }

    private static async Task<double> BurnAsync(CpuGovernor? paced, int seconds)
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

                        if (paced is not null)
                        {
                            await paced.PaceAsync(cts.Token);
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    // Expected shutdown at the end of the measurement window.
                }

                return x;
            });
        }

        var proc = Process.GetCurrentProcess();
        proc.Refresh();
        var cpuBefore = proc.TotalProcessorTime;
        var wallBefore = DateTime.UtcNow;
        await Task.WhenAll(burners);
        proc.Refresh();
        return (proc.TotalProcessorTime - cpuBefore).TotalMilliseconds
            / ((DateTime.UtcNow - wallBefore).TotalMilliseconds * Environment.ProcessorCount)
            * 100.0;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        try { Directory.Delete(_root, recursive: true); } catch { /* best effort */ }
        try { File.Delete(_dbPath); } catch { /* best effort */ }
    }

    [Fact]
    public async Task Delta_Rejects_NonFile_Paths_As_Gaps()
    {
        using var db = new Sentinel.Store.SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(
            db,
            idle: new FixedIdleProbe(TimeSpan.FromMinutes(30)),
            fullscreen: new FixedFullscreenProbe(false));
        var options = new ScanOptions(ScanMode.Balanced, [_root]);
        var real = Path.Combine(_root, "f000.bin");
        var missing = Path.Combine(_root, "nope.bin");

        var result = await orchestrator.RescanPathsAsync(
            [real, _root, missing], options, new PauseToken());

        Assert.Equal(ScanOutcome.Completed, result.Outcome);
        Assert.Equal(1, result.FilesSeen);
        Assert.Contains(result.Gaps, g => g.Path == _root);
        Assert.Contains(result.Gaps, g => g.Path == missing);
    }

    [Fact]
    public async Task Excluded_Prefix_Prunes_Subtree()
    {
        var excluded = Path.Combine(_root, "secret");
        Directory.CreateDirectory(excluded);
        File.WriteAllText(Path.Combine(excluded, "s.txt"), "hidden");
        using var db = new Sentinel.Store.SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(
            db,
            idle: new FixedIdleProbe(TimeSpan.FromMinutes(30)),
            fullscreen: new FixedFullscreenProbe(false));
        var options = new ScanOptions(ScanMode.Balanced, [_root], excludedPathPrefixes: [excluded]);

        var result = await orchestrator.RunAsync(options, new PauseToken());

        Assert.Equal(ScanOutcome.Completed, result.Outcome);
        Assert.Equal(20, result.FilesSeen);
        Assert.Contains(result.Gaps, g => g.Reason == "ExcludedScope");
        Assert.Null(db.GetFingerprint(Path.Combine(excluded, "s.txt")));
    }

    private sealed class FakeClock(int cores) : ICpuClock
    {
        private long _wall;
        private double _cpu;

        public int ProcessorCount => cores;

        public long WallMilliseconds => _wall;

        public double CpuMilliseconds => _cpu;

        public void Advance(long wallMs, double cpuMs)
        {
            _wall += wallMs;
            _cpu += cpuMs;
        }
    }

    private sealed class FixedIdleProbe(TimeSpan idle) : IIdleProbe
    {
        public TimeSpan GetIdleTime() => idle;
    }

    [Fact]
    public async Task Eco_AutoPauses_Until_User_Goes_Idle()
    {
        // Deterministic continuity check: call #1 is admission (idle),
        // calls #2-4 report activity (worker must wait ~500ms each),
        // then idle again. Single Eco worker => fixed call sequence.
        var probe = new CountingIdleProbe(activeUntilCall: 4);
        using var db = new Sentinel.Store.SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(
            db, idle: probe, fullscreen: new FixedFullscreenProbe(false));
        var sw = Stopwatch.StartNew();

        var result = await orchestrator.RunAsync(
            new ScanOptions(ScanMode.Eco, [_root]), new PauseToken());

        sw.Stop();
        Assert.Equal(ScanOutcome.Completed, result.Outcome);
        Assert.Equal(20, result.FilesSeen);
        Assert.True(sw.ElapsedMilliseconds >= 900,
            "Eco scan must wait out user activity instead of scanning through it.");
    }

    [Fact]
    public async Task Failed_Scan_Records_Status_And_Rolls_Back()
    {
        // A disposed store faults every DB call: the scan must report
        // Failed (not throw, not hang, not half-commit).
        var db = new Sentinel.Store.SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(
            db,
            idle: new FixedIdleProbe(TimeSpan.FromMinutes(30)),
            fullscreen: new FixedFullscreenProbe(false));
        db.Dispose();

        var result = await orchestrator.RunAsync(
            new ScanOptions(ScanMode.Balanced, [_root]), new PauseToken());

        Assert.Equal(ScanOutcome.Failed, result.Outcome);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public async Task Cancelled_Scan_Leaves_No_Partial_Generation()
    {
        using var db = new Sentinel.Store.SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(
            db,
            idle: new FixedIdleProbe(TimeSpan.FromMinutes(30)),
            fullscreen: new FixedFullscreenProbe(false));
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var result = await orchestrator.RunAsync(
            new ScanOptions(ScanMode.Balanced, [_root]), new PauseToken(), cts.Token);

        Assert.Equal(ScanOutcome.Cancelled, result.Outcome);
        Assert.Null(db.GetFingerprint(Path.Combine(_root, "f000.bin")));
        // Cancelled before start: no generation reserved, no row written.
        Assert.Equal(0, result.Generation);
        Assert.Null(db.GetRun(1));
    }

    private sealed class CountingIdleProbe(int activeUntilCall) : IIdleProbe
    {
        private int _calls;

        public TimeSpan GetIdleTime()
        {
            int call = Interlocked.Increment(ref _calls);
            return call > 1 && call <= activeUntilCall
                ? TimeSpan.FromSeconds(10)
                : TimeSpan.FromMinutes(30);
        }
    }

    private sealed class FixedFullscreenProbe(bool fullscreen) : IFullscreenProbe
    {
        public bool IsForegroundFullscreen() => fullscreen;
    }
}
