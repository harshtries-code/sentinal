using Sentinel.App.Services;
using Sentinel.App.ViewModels;
using Sentinel.Engine.Scan;
using Sentinel.Engine.SystemInventory;
using Sentinel.Store;

namespace Sentinel.Tests;

// Headless view-model tests: ImmediateDispatcher keeps WPF out of
// the test process. XAML itself is verified by build + manual run.
public sealed class ViewModelTests : IDisposable
{
    private readonly string _root;
    private readonly string _dbPath;
    private bool _disposed;

    public ViewModelTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "sentinel-vm-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
        for (int i = 0; i < 5; i++)
        {
            File.WriteAllText(Path.Combine(_root, $"f{i}.txt"), "data-" + i);
        }

        _dbPath = Path.Combine(Path.GetTempPath(), "sentinel-vm-" + Guid.NewGuid().ToString("N") + ".db");
    }

    private ScanSessionViewModel NewSession()
    {
        return new ScanSessionViewModel(
            () => new SentinelDb(_dbPath),
            dispatcher: new ImmediateDispatcher());
    }

    [Fact]
    public async Task Session_Start_Completes_With_Counts()
    {
        var session = NewSession();

        Assert.True(session.CanStart);
        session.Start(ScanMode.Balanced, _root);

        var result = await session.RunningTask!;

        Assert.NotNull(result);
        Assert.Equal(ScanSessionState.Completed, session.State);
        Assert.Equal(5, result.FilesSeen);
        Assert.Equal(5, result.FilesHashed);
        Assert.Contains("5 files", session.Counts);
        Assert.True(session.CanStart); // Can scan again.
    }

    [Fact]
    public async Task Session_Pause_Resume_Cancel_Transitions()
    {
        var session = NewSession();
        session.Start(ScanMode.Balanced, _root);

        session.Pause();
        Assert.Equal(ScanSessionState.Paused, session.State);
        Assert.True(session.CanResume);

        session.Resume();
        Assert.Equal(ScanSessionState.Running, session.State);

        session.Cancel();
        var result = await session.RunningTask!;

        Assert.True(result is null || result.Outcome == ScanOutcome.Cancelled
            || session.State == ScanSessionState.Completed);
        // Tiny fixture may finish before cancel lands; either end state is honest.
        Assert.True(session.State is ScanSessionState.Cancelled or ScanSessionState.Completed);
    }

    [Fact]
    public void Status_Refresh_Populates()
    {
        var missing = Path.Combine(Path.GetTempPath(), "sentinel-missing-" + Guid.NewGuid().ToString("N") + ".db");
        using var status = new StatusBarViewModel(() => missing);

        status.Refresh();

        Assert.Contains("Sentinel", status.SelfResources);
        Assert.Contains("MB", status.SelfResources);
        Assert.False(string.IsNullOrWhiteSpace(status.DefenderState));
        Assert.Equal("Never scanned", status.LastScan);
    }

    [Fact]
    public void Status_Refresh_Appends_Resource_History()
    {
        var missing = Path.Combine(Path.GetTempPath(), "sentinel-missing-" + Guid.NewGuid().ToString("N") + ".db");
        using var status = new StatusBarViewModel(() => missing);

        Assert.Empty(status.SampleHistory());
        status.Refresh();
        status.Refresh();

        var history = status.SampleHistory();
        Assert.Equal(2, history.Count);
        Assert.True(status.CurrentRamMb > 0);
        Assert.True(status.CurrentCpuPercent >= 0);
        Assert.True(history[1].AtUtc >= history[0].AtUtc);
        Assert.Equal(status.CurrentCpuPercent, history[1].CpuPercent);
        Assert.Equal(status.CurrentRamMb, history[1].RamMb);
    }

    [Fact]
    public void Overview_Refresh_Fills_Dashboard()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), "sentinel-ov-" + Guid.NewGuid().ToString("N") + ".db");
        string agentPath = Path.Combine(Path.GetTempPath(), "sentinel-ov-" + Guid.NewGuid().ToString("N") + ".adb");
        var overview = new OverviewViewModel(
            () => new SentinelDb(dbPath),
            () => new AgentStore(agentPath),
            () => []);
        overview.Refresh();

        Assert.False(string.IsNullOrWhiteSpace(overview.MachineLine));
        Assert.False(string.IsNullOrWhiteSpace(overview.HeroTitle));
        Assert.Equal("Never scanned", overview.HeroTitle); // Fresh DBs: honest empty.
        Assert.False(overview.HeroIsOk);
        Assert.Equal(6, overview.Organs.Count);
        Assert.All(overview.Organs, o => Assert.False(string.IsNullOrWhiteSpace(o.Detail)));
        Assert.Equal(6, overview.Coverage.Count);
        Assert.False(overview.HasActivity);
        Assert.False(string.IsNullOrWhiteSpace(overview.LastScanLine));
    }

    // Board 01 relationships: 153/55 group by anchored device, the
    // disk inventory resolves the label, foreign providers excluded.
    [Fact]
    public void Overview_BuildClusters_Groups_By_Anchored_Device()
    {
        var now = DateTime.UtcNow;
        var warnings = new List<TargetedEventRecord>
        {
            new("System", 1, 153, "Warning", now.AddHours(-1), "disk",
                "The IO operation for Disk 2 was retried.", []),
            new("System", 2, 153, "Warning", now.AddHours(-2), "disk",
                "The IO operation for Disk 2 (PDO Harddisk2) was retried.", []),
            new("System", 3, 55, "Error", now.AddHours(-3), "NTFS",
                "The file system structure on volume C: is corrupt.", []),
            new("System", 4, 153, "Warning", now.AddHours(-4), "Contoso-Fake",
                "Bogus 153 from a foreign provider.", []),
        };
        var topology = new List<DiskTopologyRecord>
        {
            new(2, "FAKEDISK 1TB", "SATA", "Healthy", "GPT", 1_000_000_000_000L, false, []),
        };

        var clusters = OverviewViewModel.BuildClusters(warnings, topology);

        Assert.Equal(2, clusters.Count); // Foreign 153 excluded.
        Assert.Equal(2, clusters[0].EventCount);
        Assert.True(clusters[0].HasDiskMatch);
        Assert.Contains("FAKEDISK", clusters[0].DiskDetail);
        Assert.Contains("Event 153", clusters[0].NewestSummary);
        Assert.False(clusters[1].HasDiskMatch);
    }

    // Activity merges runs + investigations newest-first, capped.
    [Fact]
    public void Overview_BuildActivity_Merges_Runs_And_Investigations()
    {
        var runs = new List<ScanRunInfo>
        {
            new(1, 1, @"C:\", "Completed", null, 100, 1000, 90, 5000, 2,
                DateTime.UtcNow.AddHours(-2).ToString("O"), "Balanced"),
        };
        var investigations = new List<InvestigationState>
        {
            new("inv-1", "seed", "seed goal", "Done", null, 1, 1, 2, 100, 5.0,
                10, 5, 0, 0, 500, true, null, "[]",
                DateTime.UtcNow.AddHours(-1).ToString("O"), null),
        };

        var activity = OverviewViewModel.BuildActivity(runs, investigations);

        Assert.Equal(2, activity.Count);
        Assert.Equal("Investigation done", activity[0].Title); // Newest first.
        Assert.Equal("Scan completed", activity[1].Title);
        Assert.Contains("100 files", activity[1].Detail);
        // A02/F11: gaps cover unreadable directories as well as files
        // (FileEnumerator records dir/root gaps), so the activity line names
        // them "locations" — matching the organ line and the Storage page.
        Assert.Contains("2 locations unavailable", activity[1].Detail);
    }

    // Zero/failed states render honest strings, never bare zeros.
    [Fact]
    public void Overview_BuildOrgans_Zero_States_Are_Honest()
    {
        var snapshot = new OverviewViewModel.OverviewSnapshot(
            CollectionResult<StartupRecord>.Ok([], "test"),
            CollectionResult<StartupRecord>.Ok([], "test"),
            CollectionResult<DriverRecord>.Ok([], "test"),
            CollectionResult<DeviceProblemRecord>.Ok([], "test"),
            CollectionResult<EventRecord>.Ok([], "test"),
            CollectionResult<TargetedEventRecord>.Ok([], "test"),
            CollectionResult<DiskTopologyRecord>.Ok([], "test"),
            CollectionResult<BatteryRecord>.Ok([], "test"),
            CollectionResult<DiskHealthRecord>.Ok([], "test"),
            CollectionResult<DefenderStatusRecord>.Fail("test", "wmi-denied"),
            CollectionResult<DefenderDetectionRecord>.Fail("test", "wmi-denied"),
            null, "DbMissing",
            [], []);

        var organs = OverviewViewModel.BuildOrgans(snapshot);

        Assert.Equal("Couldn't inspect storage", organs[0].Detail);
        Assert.False(organs[0].IsGood);
        Assert.Equal("No device problems", organs[1].Detail);
        Assert.Equal("Defender history unavailable", organs[3].Detail);
        Assert.False(organs[3].IsGood);
        Assert.Equal("No battery device", organs[5].Detail);
    }

    [Fact]
    public void Performance_Refresh_Fills_Tables()
    {
        var performance = new PerformanceViewModel();
        performance.Refresh();

        Assert.NotEmpty(performance.Processes);
        Assert.All(performance.Processes, p =>
        {
            Assert.False(string.IsNullOrWhiteSpace(p.Name));
            Assert.Contains("MB", p.Memory);
        });
        Assert.False(string.IsNullOrWhiteSpace(performance.Battery));
        Assert.False(string.IsNullOrWhiteSpace(performance.Disks));
        Assert.False(string.IsNullOrWhiteSpace(performance.Coverage));
    }

    [Fact]
    public void Performance_PublisherFor_Resolves_Or_Unknown()
    {
        string cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        if (File.Exists(cmd))
        {
            Assert.Equal(
                "Microsoft Corporation",
                PerformanceViewModel.PublisherFor($"\"{cmd}\" /c dir"));
        }

        Assert.Equal("Unknown", PerformanceViewModel.PublisherFor(""));
        Assert.Equal(
            "Unknown",
            PerformanceViewModel.PublisherFor(
                Path.Combine(Path.GetTempPath(), "sentinel-nope-" + Guid.NewGuid().ToString("N") + ".exe")));
        Assert.Equal(
            "Unknown", PerformanceViewModel.PublisherFor("sentinel-no-such-host.exe arg"));
        if (File.Exists(Path.Combine(Environment.SystemDirectory, "rundll32.exe")))
        {
            Assert.Equal(
                "Microsoft Corporation",
                PerformanceViewModel.PublisherFor("rundll32.exe shell32.dll,Open"));
        }
    }

    [Fact]
    public void Performance_SliceHistory_Ranges_And_Caps()
    {
        DateTime end = new DateTime(2026, 11, 1, 12, 0, 0, DateTimeKind.Utc);
        var history = new List<ResourceSample>();
        for (int i = 0; i < 120; i++)
        {
            history.Add(new ResourceSample(end.AddMinutes(-60 + i * 0.5), i % 10, 100 + i));
        }

        var five = PerformanceViewModel.SliceHistory(history, "Last 5 minutes");
        Assert.Equal(11, five.Count);
        Assert.All(five, p => Assert.True(p.AtUtc >= end.AddMinutes(-5.5)));
        var thirty = PerformanceViewModel.SliceHistory(history, "Last 30 minutes");
        Assert.True(thirty.Count > five.Count);
        var capped = PerformanceViewModel.SliceHistory(history, "Last 30 minutes", maxPoints: 5);
        Assert.True(capped.Count <= 6);
        Assert.Equal(history[history.Count - 1].AtUtc, capped[capped.Count - 1].AtUtc);
        Assert.Empty(PerformanceViewModel.SliceHistory([], "Last 5 minutes"));
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
}
