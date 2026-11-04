using System.Diagnostics;
using Sentinel.Engine.Watch;

namespace Sentinel.Tests;

// P21 live leg (opt-in SENTINEL_WATCH_LIVE=1): the REAL watcher with
// LIVE sources — real process snapshots, real folder events —
// against planted processes and dropped files. Primary evidence
// runs in the quiet guest; a host run is a smoke check only.
// Read-only on the machine except: plants ping.exe (harmless,
// killed after), drops one .exe-named text file in Temp (removed
// after). No files outside Temp, no settings touched.
public sealed class WatchLiveTests : IDisposable
{
    private readonly List<ProcessWatcher> _watchers = new();
    private readonly List<Process> _plants = new();
    private readonly string _dropFile;

    public WatchLiveTests()
    {
        _dropFile = Path.Combine(Path.GetTempPath(), "sentinel-watchdrop-" + Guid.NewGuid().ToString("N") + ".exe");
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

        foreach (var p in _plants)
        {
            try
            {
                if (!p.HasExited)
                {
                    p.Kill(entireProcessTree: true);
                }

                p.Dispose();
            }
            catch
            {
            }
        }

        try
        {
            File.Delete(_dropFile);
        }
        catch
        {
        }
    }

    private static void RequireLive()
    {
        Skip.IfNot(
            string.Equals(Environment.GetEnvironmentVariable("SENTINEL_WATCH_LIVE"), "1", StringComparison.Ordinal),
            "Opt-in live watcher test (SENTINEL_WATCH_LIVE=1). Runs in the quiet guest for P21 evidence.");
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

            Thread.Sleep(100);
        }

        return done();
    }

    private ProcessWatcher NewLiveWatcher(
        List<WatchCard> cards, TimeSpan sweep, TimeSpan deltaInterval, bool folders)
    {
        var options = new WatchOptions(
            sweep, TimeSpan.FromMinutes(10), 8, 20, deltaInterval,
            folders ? [Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar)] : [],
            ["*.exe"]);
        var watcher = new ProcessWatcher(
            new LiveProcessSnapshotSource(),
            folders
                ? new FolderEventSource(options.WatchFolders, options.ExeExtensions)
                : new NullFiles(),
            options);
        _watchers.Add(watcher);
        watcher.CardPublished += c =>
        {
            lock (cards)
            {
                cards.Add(c);
            }
        };
        return watcher;
    }

    private sealed class NullFiles : IFileEventSource
    {
        public event Action<string>? FileAppeared;

        public event Action? EventsMissed;

        public void Raise(string path) => FileAppeared?.Invoke(path);

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

    private Process PlantPing(int seconds)
    {
        var plant = Process.Start(new ProcessStartInfo
        {
            FileName = "ping.exe",
            Arguments = $"-n {seconds} 127.0.0.1",
            CreateNoWindow = true,
            UseShellExecute = false,
        })!;
        _plants.Add(plant);
        return plant;
    }

    [SkippableFact]
    public async Task Live_Plant_Carded_Under3s()
    {
        RequireLive();
        var cards = new List<WatchCard>();
        var watcher = NewLiveWatcher(cards, TimeSpan.FromSeconds(1), TimeSpan.FromMinutes(5), folders: false);

        watcher.Start();
        try
        {
            Assert.True(WaitFor(() => watcher.Stats.Sweeps >= 1, TimeSpan.FromSeconds(15)), "no baseline sweep");
            var plant = PlantPing(12);
            int pid = plant.Id;
            bool carded = WaitFor(
                () =>
                {
                    lock (cards)
                    {
                        return cards.Any(c => c.Pid == pid);
                    }
                },
                TimeSpan.FromSeconds(30));
            Assert.True(carded, "planted ping.exe was never carded");
            WatchCard card;
            lock (cards)
            {
                card = cards.First(c => c.Pid == pid);
            }

            Assert.Equal(WatchSource.Process, card.Source);
            Assert.True(
                card.ExePath is not null && card.ExePath.EndsWith("ping.exe", StringComparison.OrdinalIgnoreCase),
                "card exe: " + (card.ExePath ?? "<null>"));
            // Discovery-to-card: start time → observed. The plant
            // runs 12s; the sweep is 1s; the P21 bar is <3s.
            Assert.True(card.LatencyMs < 3000, $"latency {card.LatencyMs}ms over the 3s bar");
            Assert.True(
                card.Verdict is "SignedPublisher" or "Unverified" or "NotFound",
                "verdict: " + card.Verdict);
            try
            {
                plant.Kill(entireProcessTree: true);
            }
            catch
            {
            }

            await Task.CompletedTask;
        }
        finally
        {
            Assert.True(watcher.Stop());
        }
    }

    [SkippableFact]
    public async Task Live_Storm_Coalesces()
    {
        RequireLive();
        var cards = new List<WatchCard>();
        var watcher = NewLiveWatcher(cards, TimeSpan.FromSeconds(1), TimeSpan.FromMinutes(5), folders: false);

        watcher.Start();
        try
        {
            Assert.True(WaitFor(() => watcher.Stats.Sweeps >= 1, TimeSpan.FromSeconds(15)), "no baseline sweep");
            for (int i = 0; i < 10; i++)
            {
                PlantPing(15);
            }

            bool settled = WaitFor(
                () => watcher.Stats.Coalesced + watcher.Stats.CardsPublished >= 10
                    && watcher.Stats.Sweeps >= 3,
                TimeSpan.FromSeconds(45));
            Assert.True(settled, "storm never settled");
            List<WatchCard> pingCards;
            lock (cards)
            {
                pingCards = cards
                    .Where(c => c.ExePath is not null && c.ExePath.EndsWith("ping.exe", StringComparison.OrdinalIgnoreCase))
                    .ToList();
            }

            Assert.True(pingCards.Count >= 1, "no ping card at all");
            // One exe → one card; the storm folds. (Other machine
            // activity may card alongside — the ping count is the
            // assertion, not the total.)
            Assert.True(pingCards.Count == 1, $"storm produced {pingCards.Count} ping cards");
            Assert.True(watcher.Stats.Coalesced >= 9, $"coalesced={watcher.Stats.Coalesced}");
            await Task.CompletedTask;
        }
        finally
        {
            Assert.True(watcher.Stop());
        }
    }

    [SkippableFact]
    public async Task Live_FileDrop_Carded()
    {
        RequireLive();
        var cards = new List<WatchCard>();
        var watcher = NewLiveWatcher(cards, TimeSpan.FromSeconds(1), TimeSpan.FromMinutes(5), folders: true);

        watcher.Start();
        try
        {
            Assert.True(WaitFor(() => watcher.Stats.Sweeps >= 1, TimeSpan.FromSeconds(15)), "no baseline sweep");
            var dropUtc = DateTime.UtcNow;
            File.WriteAllText(_dropFile, "not-really-an-exe");
            bool carded = WaitFor(
                () =>
                {
                    lock (cards)
                    {
                        return cards.Any(c =>
                            c.Source == WatchSource.File
                            && string.Equals(c.ExePath, _dropFile, StringComparison.OrdinalIgnoreCase));
                    }
                },
                TimeSpan.FromSeconds(30));
            Assert.True(carded, "dropped file was never carded");
            WatchCard card;
            lock (cards)
            {
                card = cards.First(c => string.Equals(c.ExePath, _dropFile, StringComparison.OrdinalIgnoreCase));
            }

            Assert.Equal("Unverified", card.Verdict);
            Assert.False(string.IsNullOrWhiteSpace(card.Sha256));
            Assert.True(
                (card.ObservedUtc - dropUtc).TotalMilliseconds < 3000,
                $"drop-to-card {(card.ObservedUtc - dropUtc).TotalMilliseconds}ms over the 3s bar");
            await Task.CompletedTask;
        }
        finally
        {
            Assert.True(watcher.Stop());
        }
    }

    [SkippableFact]
    public async Task Live_QuietWindow_ActiveUnder2Percent()
    {
        RequireLive();
        double maxPercent = 2.0;
        string? overrideMax = Environment.GetEnvironmentVariable("SENTINEL_WATCH_CPU_MAX");
        if (overrideMax is not null && double.TryParse(
            overrideMax, System.Globalization.NumberStyles.Float,
            System.Globalization.CultureInfo.InvariantCulture, out double parsed) && parsed > 0)
        {
            maxPercent = parsed;
        }

        var cards = new List<WatchCard>();
        var watcher = NewLiveWatcher(cards, TimeSpan.FromSeconds(2), TimeSpan.FromMinutes(5), folders: false);

        watcher.Start();
        try
        {
            Assert.True(WaitFor(() => watcher.Stats.Sweeps >= 1, TimeSpan.FromSeconds(15)), "no baseline sweep");
            long activeBefore = watcher.Stats.ActiveMs;
            var wall = Stopwatch.StartNew();
            await Task.Delay(TimeSpan.FromSeconds(30));
            wall.Stop();
            double percent = (watcher.Stats.ActiveMs - activeBefore) / wall.Elapsed.TotalMilliseconds * 100.0;
            Assert.True(percent < maxPercent, $"watcher active {percent:F2}% over the {maxPercent}% bar");
        }
        finally
        {
            Assert.True(watcher.Stop());
        }
    }
}
