using System.Collections.Concurrent;
using Sentinel.Engine.SystemInventory;
using Sentinel.Engine.Watch;

namespace Sentinel.Tests;

// P21: automatic priority watching over scripted sources (the A04
// fixture: reuse, exited, protected, storm, scope, stop). Scripts
// carry PIDs only — exactly the live CollectLight shape — and a
// scripted identity resolver binds name/start/path per arrival.
// Timing is poll-with-timeout, never fixed sleeps.
public sealed class WatchTests : IDisposable
{
    private readonly string _root;
    private readonly List<ProcessWatcher> _watchers = new();

    public WatchTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "sentinel-p21-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        foreach (var w in _watchers)
        {
            try
            {
                w.Dispose();
            }
            catch
            {
            }
        }

        try
        {
            Directory.Delete(_root, true);
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

        public int Calls => Volatile.Read(ref _calls);

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

    // Live-shaped row: PID only, like CollectLight.
    private static ProcessRecord Row(int pid) =>
        new(pid, string.Empty, null, null, null, null, 0);

    private static WatchOptions FastOptions() => new(
        TimeSpan.FromMilliseconds(50),
        TimeSpan.FromMinutes(10),
        8,
        20,
        TimeSpan.FromMilliseconds(100),
        [],
        []);

    private ProcessWatcher NewWatcher(
        ScriptedSnapshots snaps,
        ScriptedFiles files,
        ConcurrentBag<WatchCard> cards,
        ConcurrentBag<IReadOnlyList<string>> deltas,
        Func<int, ProcessIdentity?>? resolver = null,
        Func<IReadOnlyList<string>>? excluded = null,
        WatchOptions? options = null)
    {
        var watcher = new ProcessWatcher(
            snaps, files, options ?? FastOptions(),
            excluded ?? (() => []),
            resolver ?? (_ => null));
        _watchers.Add(watcher);
        watcher.CardPublished += cards.Add;
        watcher.DeltaReady += deltas.Add;
        return watcher;
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
    public void BaselineSuppressed_NewArrival_Carded()
    {
        var t0 = new DateTime(2026, 11, 3, 0, 0, 0, DateTimeKind.Utc);
        string exe = Path.Combine(_root, "app.exe");
        File.WriteAllText(exe, "fake-exe");
        // PIDs above 2^31/1000 can never exist on Windows: the
        // verdict path is deterministic (NotFound) on any host.
        const int arrivalPid = 2_000_000_000;
        var snaps = new ScriptedSnapshots(
        [
            [Row(100)],
            [Row(100), Row(arrivalPid)],
        ]);
        var files = new ScriptedFiles();
        var cards = new ConcurrentBag<WatchCard>();
        var deltas = new ConcurrentBag<IReadOnlyList<string>>();
        var watcher = NewWatcher(
            snaps, files, cards, deltas,
            pid => pid == arrivalPid ? new ProcessIdentity(pid, "app", t0, exe) : null);

        watcher.Start();
        try
        {
            Assert.True(WaitFor(() => cards.Count >= 1, TimeSpan.FromSeconds(10)), "no card for the arrival");
            var card = Assert.Single(cards);
            Assert.Equal(arrivalPid, card.Pid);
            Assert.Equal(WatchSource.Process, card.Source);
            Assert.Equal("NotFound", card.Verdict);
            Assert.Equal("app", card.Name);
            Assert.Equal(exe, card.ExePath);
            Assert.True(WaitFor(() => snaps.Calls >= 4, TimeSpan.FromSeconds(10)));
            Assert.Single(cards); // No repeats on later sweeps.
        }
        finally
        {
            Assert.True(watcher.Stop());
        }
    }

    [Fact]
    public void PidReuse_ExitAndRebirth_NewCard()
    {
        var t2 = new DateTime(2026, 11, 3, 0, 5, 0, DateTimeKind.Utc);
        string exe = Path.Combine(_root, "svc.exe");
        File.WriteAllText(exe, "v1");
        var snaps = new ScriptedSnapshots(
        [
            [Row(300)],
            [Row(300), Row(400)],
            [Row(400)],
            [Row(400), Row(300)],
        ]);
        var files = new ScriptedFiles();
        var cards = new ConcurrentBag<WatchCard>();
        var deltas = new ConcurrentBag<IReadOnlyList<string>>();
        var watcher = NewWatcher(
            snaps, files, cards, deltas,
            pid => pid == 300
                ? new ProcessIdentity(pid, "svc", t2, exe)
                : new ProcessIdentity(pid, "other", t2, null));

        watcher.Start();
        try
        {
            // Sweep 2 cards pid 400 (pathless). Sweep 4 re-cards pid
            // 300 after its exit — same PID, new lifetime. The card
            // must carry the rebound start time, proving the binding
            // moved instead of trusting the stale stamp.
            Assert.True(WaitFor(() => snaps.Calls >= 5, TimeSpan.FromSeconds(10)));
            var reuse = cards.Where(c => c.Pid == 300).ToList();
            var single = Assert.Single(reuse);
            Assert.Equal(t2, single.ProcessStartUtc);
        }
        finally
        {
            Assert.True(watcher.Stop());
        }
    }

    [Fact]
    public void ReuseDuringVerdict_Dropped_ThenRediscovered()
    {
        var t1 = new DateTime(2026, 11, 3, 0, 0, 0, DateTimeKind.Utc);
        var t2 = t1.AddMinutes(5);
        string exe = Path.Combine(_root, "race.exe");
        File.WriteAllText(exe, "v1");
        var snaps = new ScriptedSnapshots(
        [
            [],
            [Row(500)],
            [Row(500)],
            [Row(500)],
            [Row(500)],
        ]);
        var files = new ScriptedFiles();
        var cards = new ConcurrentBag<WatchCard>();
        var deltas = new ConcurrentBag<IReadOnlyList<string>>();
        // Bind sees T1; the verdict-time re-resolve sees T2 (drop +
        // snooze release); every later resolve sees T1 again, so
        // re-discovery cards honestly. If the drop forgot to release
        // the snooze stamp, no card ever appears and this times out.
        int resolves = 0;
        var watcher = NewWatcher(
            snaps, files, cards, deltas,
            pid => new ProcessIdentity(
                pid, "race",
                Interlocked.Increment(ref resolves) == 2 ? t2 : t1,
                exe));

        watcher.Start();
        try
        {
            Assert.True(WaitFor(() => cards.Count >= 1, TimeSpan.FromSeconds(10)), "re-discovery never carded");
            var card = Assert.Single(cards);
            Assert.Equal(500, card.Pid);
            Assert.Equal(t1, card.ProcessStartUtc);
        }
        finally
        {
            Assert.True(watcher.Stop());
        }
    }

    [Fact]
    public void Pathless_RebirthWithinCooldown_CardedOnce()
    {
        var t0 = new DateTime(2026, 11, 3, 0, 0, 0, DateTimeKind.Utc);
        var snaps = new ScriptedSnapshots(
        [
            [],
            [Row(600)],
            [],
            [Row(600)],
            [Row(600)],
        ]);
        var files = new ScriptedFiles();
        var cards = new ConcurrentBag<WatchCard>();
        var deltas = new ConcurrentBag<IReadOnlyList<string>>();
        var watcher = NewWatcher(
            snaps, files, cards, deltas,
            pid => new ProcessIdentity(pid, "sys", t0, null));

        watcher.Start();
        try
        {
            Assert.True(WaitFor(() => cards.Count >= 1, TimeSpan.FromSeconds(10)));
            Assert.True(WaitFor(() => snaps.Calls >= 5, TimeSpan.FromSeconds(10)));
            Thread.Sleep(150); // Let the rebirth sweep drain.
            var card = Assert.Single(cards);
            Assert.Equal("NoPath", card.Verdict);
            Assert.True(watcher.Stats.Coalesced >= 1);
        }
        finally
        {
            Assert.True(watcher.Stop());
        }
    }

    [Fact]
    public void ExitedBeforeBind_CardedHonestly()
    {
        var snaps = new ScriptedSnapshots(
        [
            [],
            [Row(700)],
            [Row(700)],
        ]);
        var files = new ScriptedFiles();
        var cards = new ConcurrentBag<WatchCard>();
        var deltas = new ConcurrentBag<IReadOnlyList<string>>();
        var watcher = NewWatcher(snaps, files, cards, deltas, _ => null);

        watcher.Start();
        try
        {
            Assert.True(WaitFor(() => cards.Count >= 1, TimeSpan.FromSeconds(10)));
            var card = Assert.Single(cards);
            Assert.Equal(700, card.Pid);
            Assert.Equal("ExitedBeforeBind", card.Verdict);
            Assert.Equal("PID 700", card.Name);
        }
        finally
        {
            Assert.True(watcher.Stop());
        }
    }

    [Fact]
    public void FileStorm_Coalesces_ToOneCard()
    {
        string exe = Path.Combine(_root, "drop.exe");
        File.WriteAllText(exe, "payload");
        var snaps = new ScriptedSnapshots([[]]);
        var files = new ScriptedFiles();
        var cards = new ConcurrentBag<WatchCard>();
        var deltas = new ConcurrentBag<IReadOnlyList<string>>();
        var watcher = NewWatcher(snaps, files, cards, deltas);

        watcher.Start();
        try
        {
            Assert.True(WaitFor(() => watcher.Stats.Sweeps >= 1, TimeSpan.FromSeconds(10)));
            for (int i = 0; i < 50; i++)
            {
                files.Emit(exe);
            }

            Assert.True(WaitFor(() => cards.Count >= 1, TimeSpan.FromSeconds(10)), "storm produced no card");
            Assert.True(WaitFor(() => watcher.Stats.Coalesced >= 49, TimeSpan.FromSeconds(10)), "storm not coalesced");
            var card = Assert.Single(cards);
            Assert.Equal(WatchSource.File, card.Source);
            Assert.Equal("Unverified", card.Verdict);
            Assert.False(string.IsNullOrWhiteSpace(card.Sha256));
        }
        finally
        {
            Assert.True(watcher.Stop());
        }
    }

    [Fact]
    public void ChangedExe_Recards()
    {
        string exe = Path.Combine(_root, "upd.exe");
        File.WriteAllText(exe, "v1");
        var snaps = new ScriptedSnapshots([[]]);
        var files = new ScriptedFiles();
        var cards = new ConcurrentBag<WatchCard>();
        var deltas = new ConcurrentBag<IReadOnlyList<string>>();
        var watcher = NewWatcher(snaps, files, cards, deltas);

        watcher.Start();
        try
        {
            Assert.True(WaitFor(() => watcher.Stats.Sweeps >= 1, TimeSpan.FromSeconds(10)));
            files.Emit(exe);
            Assert.True(WaitFor(() => cards.Count >= 1, TimeSpan.FromSeconds(10)));
            File.WriteAllText(exe, "v2-longer-bytes");
            files.Emit(exe);
            Assert.True(WaitFor(() => cards.Count >= 2, TimeSpan.FromSeconds(10)), "changed exe never re-carded");
            Assert.Equal(2, cards.Count);
        }
        finally
        {
            Assert.True(watcher.Stop());
        }
    }

    [Fact]
    public void Excluded_Paths_Skipped_WithCounter()
    {
        string skip = Path.Combine(_root, "skip");
        Directory.CreateDirectory(skip);
        string exe = Path.Combine(skip, "x.exe");
        File.WriteAllText(exe, "x");
        var t0 = new DateTime(2026, 11, 3, 0, 0, 0, DateTimeKind.Utc);
        var snaps = new ScriptedSnapshots(
        [
            [],
            [Row(800)],
            [Row(800)],
        ]);
        var files = new ScriptedFiles();
        var cards = new ConcurrentBag<WatchCard>();
        var deltas = new ConcurrentBag<IReadOnlyList<string>>();
        var watcher = NewWatcher(
            snaps, files, cards, deltas,
            pid => new ProcessIdentity(pid, "x", t0, exe),
            () => [skip]);

        watcher.Start();
        try
        {
            files.Emit(exe);
            Assert.True(WaitFor(() => snaps.Calls >= 3, TimeSpan.FromSeconds(10)));
            Thread.Sleep(150);
            Assert.Empty(cards);
            Assert.Empty(deltas.SelectMany(d => d));
            Assert.True(watcher.Stats.ExcludedSkipped >= 2, $"skipped={watcher.Stats.ExcludedSkipped}");
        }
        finally
        {
            Assert.True(watcher.Stop());
        }
    }

    [Fact]
    public void SweepCap_Drops_Retries_NextSweep()
    {
        var t0 = new DateTime(2026, 11, 3, 0, 0, 0, DateTimeKind.Utc);
        var rows = new List<ProcessRecord>();
        var exes = new Dictionary<int, string>();
        for (int i = 0; i < 6; i++)
        {
            string exe = Path.Combine(_root, $"c{i}.exe");
            File.WriteAllText(exe, "c" + i);
            rows.Add(Row(900 + i));
            exes[900 + i] = exe;
        }

        var snaps = new ScriptedSnapshots([[], rows]);
        var files = new ScriptedFiles();
        var cards = new ConcurrentBag<WatchCard>();
        var deltas = new ConcurrentBag<IReadOnlyList<string>>();
        var options = FastOptions() with { MaxVerdictsPerSweep = 2 };
        var watcher = NewWatcher(
            snaps, files, cards, deltas,
            pid => new ProcessIdentity(pid, "c" + pid, t0, exes[pid]),
            () => [], options);

        watcher.Start();
        try
        {
            // 6 arrivals, cap 2/sweep: all 6 card within 3 sweeps —
            // backpressure, never loss.
            Assert.True(WaitFor(() => cards.Count >= 6, TimeSpan.FromSeconds(15)), $"only {cards.Count} cards");
            Assert.True(watcher.Stats.DroppedOverCap >= 1);
        }
        finally
        {
            Assert.True(watcher.Stop());
        }
    }

    [Fact]
    public void DeltaReady_Batches_Paths()
    {
        string exe = Path.Combine(_root, "d.exe");
        File.WriteAllText(exe, "d");
        var snaps = new ScriptedSnapshots([[]]);
        var files = new ScriptedFiles();
        var cards = new ConcurrentBag<WatchCard>();
        var deltas = new ConcurrentBag<IReadOnlyList<string>>();
        var watcher = NewWatcher(snaps, files, cards, deltas);

        watcher.Start();
        try
        {
            Assert.True(WaitFor(() => watcher.Stats.Sweeps >= 1, TimeSpan.FromSeconds(10)));
            files.Emit(exe);
            Assert.True(WaitFor(() => deltas.Count >= 1, TimeSpan.FromSeconds(10)), "no delta batch");
            Assert.Contains(deltas.SelectMany(d => d), p => p.Equals(exe, StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Assert.True(watcher.Stop());
        }
    }

    [Fact]
    public void Stop_Joins_Restart_Works()
    {
        var snaps = new ScriptedSnapshots([[]]);
        var files = new ScriptedFiles();
        var cards = new ConcurrentBag<WatchCard>();
        var deltas = new ConcurrentBag<IReadOnlyList<string>>();
        var watcher = NewWatcher(snaps, files, cards, deltas);

        Assert.False(watcher.IsRunning);
        watcher.Start();
        Assert.True(watcher.IsRunning);
        Assert.True(WaitFor(() => watcher.Stats.Sweeps >= 1, TimeSpan.FromSeconds(10)));
        Assert.True(watcher.Stop());
        Assert.False(watcher.IsRunning);
        long sweeps = watcher.Stats.Sweeps;
        Thread.Sleep(150);
        Assert.Equal(sweeps, watcher.Stats.Sweeps); // Nothing runs after Stop.
        watcher.Start();
        Assert.True(WaitFor(() => watcher.Stats.Sweeps > sweeps, TimeSpan.FromSeconds(10)), "restart dead");
        Assert.True(watcher.Stop());
    }
}
