using Sentinel.App.Services;
using Sentinel.App.ViewModels;
using Sentinel.Engine.Scan;
using Sentinel.Engine.SystemInventory;
using Sentinel.Engine.Watch;
using Sentinel.Store;

namespace Sentinel.Tests;

// P21 app wiring: settings toggle → watcher lifecycle, cards →
// Threats feed, delta lane policy (live-insert vs bounded rescan),
// status-bar line. Scripted watcher sources; real session + store.
public sealed class WatchAppTests : IDisposable
{
    private readonly string _dir;
    private readonly string _dbPath;
    private readonly string _settingsPath;
    private readonly List<MainViewModel> _mains = new();

    public WatchAppTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "sentinel-p21app-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _dbPath = Path.Combine(_dir, "scan.db");
        _settingsPath = Path.Combine(_dir, "settings.json");
    }

    public void Dispose()
    {
        foreach (var main in _mains)
        {
            try
            {
                main.Shutdown();
            }
            catch
            {
            }
        }

        try
        {
            Directory.Delete(_dir, true);
        }
        catch
        {
        }
    }

    private sealed class ScriptedSnapshots : IProcessSnapshotSource
    {
        private readonly List<IReadOnlyList<ProcessRecord>> _script;
        private int _calls;

        public ScriptedSnapshots(List<IReadOnlyList<ProcessRecord>> script)
        {
            _script = script;
        }

        public IReadOnlyList<ProcessRecord> Snapshot()
        {
            int n = Interlocked.Increment(ref _calls) - 1;
            return _script[Math.Min(n, _script.Count - 1)];
        }
    }

    private sealed class ScriptedFiles : IFileEventSource
    {
        public event Action<string>? FileAppeared;

        public event Action? EventsMissed;

        public void Emit(string path) => FileAppeared?.Invoke(path);

        public void Miss() => EventsMissed?.Invoke();

        public void Start()
        {
        }

        public void Stop()
        {
        }

        public void Dispose()
        {
        }
    }

    private static WatchOptions FastOptions() => new(
        TimeSpan.FromMilliseconds(50),
        TimeSpan.FromMinutes(10),
        8,
        20,
        TimeSpan.FromMilliseconds(100),
        [],
        []);

    private MainViewModel NewMain(
        ScriptedSnapshots snaps, ScriptedFiles files,
        Func<int, ProcessIdentity?>? resolver = null)
    {
        var main = new MainViewModel(
            () => new SentinelDb(_dbPath),
            new ImmediateDispatcher(),
            _dbPath,
            () => new ProcessWatcher(snaps, files, FastOptions(), () => [], resolver ?? (_ => null)),
            _settingsPath);
        _mains.Add(main);
        return main;
    }

    private static bool WaitFor(Func<bool> done, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (done())
            {
                return true;
            }

            Thread.Sleep(20);
        }

        return done();
    }

    [Fact]
    public void SettingsToggle_Starts_Stops_Watch()
    {
        var main = NewMain(
            new ScriptedSnapshots([[]]),
            new ScriptedFiles());

        Assert.True(main.Settings.PriorityWatchEnabled);
        main.StartWatching();
        Assert.True(main.IsWatching);

        main.Settings.PriorityWatchEnabled = false;
        Assert.False(main.IsWatching);
        Assert.Contains("off", main.Threats.WatchLine);

        main.Settings.PriorityWatchEnabled = true;
        Assert.True(main.IsWatching);

        main.Shutdown();
        Assert.False(main.IsWatching);
    }

    [Fact]
    public void WatchCard_Reaches_ThreatsFeed_WithLine()
    {
        var t0 = new DateTime(2026, 11, 3, 0, 0, 0, DateTimeKind.Utc);
        string exe = Path.Combine(_dir, "app.exe");
        File.WriteAllText(exe, "fake-exe");
        var snaps = new ScriptedSnapshots(
        [
            [],
            [new ProcessRecord(2_000_000_000, string.Empty, null, null, null, null, 0)],
        ]);
        var main = NewMain(
            snaps, new ScriptedFiles(),
            pid => new ProcessIdentity(pid, "app", t0, exe));

        main.StartWatching();
        try
        {
            Assert.True(WaitFor(() => main.Threats.WatchFeed.Count >= 1, TimeSpan.FromSeconds(10)));
            var row = Assert.Single(main.Threats.WatchFeed);
            Assert.Contains("app", row.Name);
            Assert.Equal("NotFound", row.Verdict); // Impossible PID: honest label.
            Assert.Equal("process", row.Source);
            Assert.Contains("1 new", main.Threats.WatchLine);
        }
        finally
        {
            main.Shutdown();
        }
    }

    [Fact]
    public void Delta_IdleSession_RunsBoundedRescan()
    {
        string exe = Path.Combine(_dir, "delta.exe");
        File.WriteAllText(exe, "delta-bytes");
        var files = new ScriptedFiles();
        var main = NewMain(new ScriptedSnapshots([[]]), files);

        main.StartWatching();
        try
        {
            Assert.True(WaitFor(() => (main.WatchStats?.Sweeps ?? 0) >= 1, TimeSpan.FromSeconds(10)));
            files.Emit(exe);

            // The bounded delta rescans the path: its fingerprint
            // appears without any manual scan.
            bool fingerprinted = WaitFor(
                () =>
                {
                    try
                    {
                        using var db = new SentinelDb(_dbPath);
                        return db.GetFingerprint(exe) is not null;
                    }
                    catch
                    {
                        return false;
                    }
                },
                TimeSpan.FromSeconds(30));
            Assert.True(fingerprinted, "watcher delta never fingerprinted the path");
        }
        finally
        {
            main.Shutdown();
        }
    }

    [SkippableFact]
    public async Task Delta_PausedSession_LiveInserts_SameGeneration()
    {
        string scope = Path.Combine(_dir, "scope");
        Directory.CreateDirectory(scope);
        var payload = new byte[64 * 1024];
        new Random(11).NextBytes(payload);
        for (int i = 0; i < 200; i++)
        {
            File.WriteAllBytes(Path.Combine(scope, $"w{i:D4}.bin"), payload);
        }

        string exe = Path.Combine(_dir, "live.exe");
        File.WriteAllText(exe, "live-bytes");
        var files = new ScriptedFiles();
        var main = NewMain(new ScriptedSnapshots([[]]), files);

        main.StartWatching();
        try
        {
            Assert.True(WaitFor(() => (main.WatchStats?.Sweeps ?? 0) >= 1, TimeSpan.FromSeconds(10)));
            main.Session.Start(ScanMode.Balanced, scope);
            main.Session.Pause();
            if (main.Session.State != ScanSessionState.Paused)
            {
                // The scan drained before the pause landed — the
                // host is too fast to prove mid-scan insertion
                // (same honest skip as the R5 plant test).
                main.Session.Cancel();
                await main.Session.RunningTask!;
                Skip.If(true, "Scan drained before pause — host too fast.");
            }

            files.Emit(exe);
            Assert.True(
                WaitFor(() => (main.WatchStats?.DeltaPathsQueued ?? 0) >= 1, TimeSpan.FromSeconds(10)),
                "watcher never queued the delta");
            // Let the lane branch run (priority insert, not rescan).
            await Task.Delay(500);
            main.Session.Resume();
            var result = await main.Session.RunningTask!;

            Assert.NotNull(result);
            Assert.Equal(ScanSessionState.Completed, main.Session.State);
            using var db = new SentinelDb(_dbPath);
            var fp = db.GetFingerprint(exe);
            Assert.NotNull(fp);
            // Same generation as the running scan: the priority
            // lane absorbed it (a delta rescan would stamp +1).
            Assert.Equal(result.Generation, fp.LastSeenGeneration);
        }
        finally
        {
            main.Shutdown();
        }
    }

    [Fact]
    public void Threats_Feed_Cap_Clear_And_ApplyPreserves()
    {
        var threats = new ThreatsViewModel();
        var card = new WatchCard(
            1, null, "a", Path.Combine(_dir, "a.exe"), "Unverified",
            "detail", null, null, WatchSource.Process, DateTime.UtcNow, 5, 0);

        for (int i = 0; i < ThreatsViewModel.MaxWatchFeed + 10; i++)
        {
            threats.AddWatchCard(card with { Pid = 1000 + i });
        }

        Assert.Equal(ThreatsViewModel.MaxWatchFeed, threats.WatchFeed.Count);
        Assert.Contains("PID 1109", threats.WatchFeed[0].Name); // Newest first.

        var coalesced = card with { CoalescedCount = 3 };
        threats.AddWatchCard(coalesced);
        Assert.Contains("+3 similar", threats.WatchFeed[0].Detail);

        // A page collect/apply must never wipe the live feed.
        threats.Apply(ThreatsViewModel.Collect());
        Assert.Equal(ThreatsViewModel.MaxWatchFeed, threats.WatchFeed.Count);

        threats.ClearWatchFeed();
        Assert.Empty(threats.WatchFeed);
    }

    [Fact]
    public void StatusBar_WatchLine_FollowsProvider()
    {
        using var status = new StatusBarViewModel(() => _dbPath + ".missing");

        status.Refresh();
        Assert.Equal("Watch: off", status.WatchLine);

        status.WatchLineProvider = () => "Watch: on · 2 new · 0.1% active";
        status.Refresh();
        Assert.Equal("Watch: on · 2 new · 0.1% active", status.WatchLine);

        status.WatchLineProvider = () => throw new InvalidOperationException("boom");
        status.Refresh();
        Assert.Equal("Watch: unavailable", status.WatchLine);
    }
}
