using Sentinel.App.ViewModels;
using Sentinel.Engine.Scan;
using Sentinel.Engine.SystemInventory;
using Sentinel.Store;

namespace Sentinel.Tests;

// P27: performance + health evidence — drive free-space history
// (schema v2), crash-trend rendering, sampled per-process CPU,
// session IO, and last-scan cost. Live-collector assertions check
// shape and bounds, never fixed machine data.
public sealed class PerformanceHealthTests : IDisposable
{
    private readonly string _dir;

    public PerformanceHealthTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "sentinel-p27-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, true);
        }
        catch
        {
        }
    }

    private string Anchor(string name = "passport.db") => Path.Combine(_dir, name);

    [Fact]
    public void DriveSamples_RoundTrip_NormalizedAndOrdered()
    {
        string path = Anchor();
        DateTime now = DateTime.UtcNow;
        using (var store = new PassportDb(path))
        {
            store.RecordDriveSample("c:", now.AddDays(-7), 26306674688, 100000000000);
            store.RecordDriveSample("C:", now, 25880256512, 100000000000);
        }

        using var reopened = new PassportDb(path);
        Assert.Equal(["C:"], reopened.QueryDriveKeys());
        var rows = reopened.QueryDriveTrend("c:");
        Assert.Equal(2, rows.Count);
        Assert.Equal(25880256512, rows[0].FreeBytes); // Newest first.
        Assert.Equal(26306674688, rows[1].FreeBytes);
    }

    [Fact]
    public void DriveSamples_PruneBeyond90Days_OnRecord()
    {
        string path = Anchor();
        DateTime now = DateTime.UtcNow;
        using (var store = new PassportDb(path))
        {
            store.RecordDriveSample("C:", now.AddDays(-91), 1, 100);
            store.RecordDriveSample("C:", now.AddDays(-89), 2, 100);
            store.RecordDriveSample("C:", now, 3, 100);

            var rows = store.QueryDriveTrend("C:");
            Assert.Equal(2, rows.Count);
            Assert.DoesNotContain(rows, r => r.FreeBytes == 1);
        }
    }

    [Fact]
    public void DriveSamples_SameStamp_Upserts()
    {
        string path = Anchor();
        DateTime now = DateTime.UtcNow;
        using (var store = new PassportDb(path))
        {
            store.RecordDriveSample("C:", now, 1, 100);
            store.RecordDriveSample("C:", now, 2, 100);

            var rows = store.QueryDriveTrend("C:");
            var single = Assert.Single(rows);
            Assert.Equal(2, single.FreeBytes);
        }
    }

    [Fact]
    public void SchemaV1_MigratesToV2_PreservingRuns()
    {
        string path = Anchor();
        using (var conn = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={path}"))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE ScanRuns(
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    StartedUtc TEXT NOT NULL,
                    Root TEXT NOT NULL,
                    Generation INTEGER NOT NULL,
                    FilesSeen INTEGER NOT NULL DEFAULT 0,
                    BytesSeen INTEGER NOT NULL DEFAULT 0,
                    FilesHashed INTEGER NOT NULL DEFAULT 0,
                    DurationMs INTEGER NOT NULL DEFAULT 0,
                    Status TEXT NOT NULL DEFAULT 'Running',
                    Error TEXT NULL,
                    GapsCount INTEGER NOT NULL DEFAULT 0,
                    Mode TEXT NOT NULL DEFAULT 'Unknown');
                INSERT INTO ScanRuns(StartedUtc, Root, Generation, FilesSeen)
                VALUES ('2026-01-01T00:00:00Z', 'C:\\', 7, 42);
                PRAGMA user_version = 1;
                """;
            cmd.ExecuteNonQuery();
        }

        using (var store = new PassportDb(path))
        {
            store.RecordDriveSample("C:", DateTime.UtcNow, 9, 100);
            Assert.Single(store.QueryDriveTrend("C:"));
        }

        using (var conn = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={path}"))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "PRAGMA user_version;";
            Assert.Equal(PassportDb.SchemaVersion, Convert.ToInt32(cmd.ExecuteScalar()));
        }

        using var reopened = new PassportDb(path);
        var run = Assert.Single(reopened.ListRuns(10));
        Assert.Equal(7, run.Generation);
        Assert.Equal(42, run.FilesSeen);
    }

    [Fact]
    public void FormatDriveTrend_CoversEmptySingleAndRange()
    {
        Assert.Equal("C:: no history yet.",
            PerformanceViewModel.FormatDriveTrend("C:", []));

        var single = new DriveFreeSample("C:", DateTime.UtcNow.ToString("O"), 26306674688, 100000000000);
        Assert.Equal("C:: 24.5 GB free (first reading just now).",
            PerformanceViewModel.FormatDriveTrend("C:", [single]));

        DateTime now = DateTime.UtcNow;
        var newest = new DriveFreeSample("C:", now.ToString("O"), 25880256512, 100000000000);
        var oldest = new DriveFreeSample("C:", now.AddDays(-7).ToString("O"), 26306674688, 100000000000);
        Assert.Equal("C:: 24.5 → 24.1 GB free (7 days).",
            PerformanceViewModel.FormatDriveTrend("C:", [newest, oldest]));
    }

    [Fact]
    public void FormatCrashTrend_CoversEmptyAndCounts()
    {
        Assert.Equal("No crashes recorded in the last 4 weeks.",
            PerformanceViewModel.FormatCrashTrend([]));
        Assert.Equal("No crashes recorded in the last 4 weeks.",
            PerformanceViewModel.FormatCrashTrend(
                [new CrashWeek("2026-10-01T00:00:00Z", 0), new CrashWeek("2026-10-08T00:00:00Z", 0)]));
        Assert.Equal("3 crashes recorded in the last 4 weeks (2 this week).",
            PerformanceViewModel.FormatCrashTrend(
                [new CrashWeek("2026-10-01T00:00:00Z", 1), new CrashWeek("2026-10-08T00:00:00Z", 2)]));
        Assert.Equal("1 crash recorded in the last 4 weeks.",
            PerformanceViewModel.FormatCrashTrend(
                [new CrashWeek("2026-10-01T00:00:00Z", 1), new CrashWeek("2026-10-08T00:00:00Z", 0)]));
    }

    [Fact]
    public void FormatScanCost_CoversMissingCompletedAndRefused()
    {
        Assert.Equal("No scan has run yet.",
            PerformanceViewModel.FormatScanCost(null, string.Empty));

        var done = new OrchestratedScanResult(
            ScanOutcome.Completed, 7, 4102, 9_000_000_000, 100, [],
            TimeSpan.FromSeconds(12.4), null);
        Assert.Equal("4,102 files · 8.4 GB in 12.4s · C:\\Docs · Completed.",
            PerformanceViewModel.FormatScanCost(done, @"C:\Docs"));

        var refused = new OrchestratedScanResult(
            ScanOutcome.RefusedLowPower, 0, 0, 0, 0, [],
            TimeSpan.Zero, "Eco scans run only when the PC is idle and charged.");
        Assert.Contains("RefusedLowPower", PerformanceViewModel.FormatScanCost(refused, @"C:\Docs"));
        Assert.DoesNotContain("0 files", PerformanceViewModel.FormatScanCost(refused, @"C:\Docs"));
    }

    [Fact]
    public void FormatIo_And_SampleDefaults()
    {
        Assert.Equal("Read 12 MB · Wrote 3 MB", PerformanceViewModel.FormatIo(12.4, 3.1));

        var legacy = new ResourceSample(DateTime.UtcNow, 1.0, 2.0);
        Assert.Equal(0, legacy.IoReadMb);
        Assert.Equal(0, legacy.IoWriteMb);
    }

    [Fact]
    public void StatusBar_Samples_CarryNonNegativeIo()
    {
        using var status = new StatusBarViewModel(() => Path.Combine(_dir, "unused.db"));
        status.Refresh();
        status.Refresh();

        var history = status.SampleHistory();
        Assert.NotEmpty(history);
        var last = history[history.Count - 1];
        Assert.True(last.IoReadMb >= 0);
        Assert.True(last.IoWriteMb >= 0);
    }

    [Fact]
    public void CollectTopCpu_ReturnsBoundedSaneSamples()
    {
        var rows = ProcessCollector.CollectTopCpu(25, 100);

        Assert.True(rows.Count <= 25);
        Assert.NotEmpty(rows);
        foreach (var row in rows)
        {
            Assert.True(row.Id > 0);
            if (row.CpuPercent is not null)
            {
                Assert.InRange(row.CpuPercent.Value, 0, 100.0);
            }
        }
    }

    [Fact]
    public void CollectNow_RecordsSamples_AndRendersTrends()
    {
        string path = Anchor();
        var vm = new PerformanceViewModel(() => new PassportDb(path), () => "scan cost line");
        var snapshot = vm.CollectNow([]);

        Assert.Equal("scan cost line", snapshot.ScanCost);
        Assert.NotEmpty(snapshot.DriveTrends);
        Assert.Contains(snapshot.DriveTrends, t => t.Drive == "C:");
        Assert.False(string.IsNullOrWhiteSpace(snapshot.CrashTrend));
        Assert.Null(vm.LastPersistError);

        // A second visit inside the hour records nothing new.
        using var store = new PassportDb(path);
        int before = store.QueryDriveTrend("C:").Count;
        vm.CollectNow([]);
        using var reread = new PassportDb(path);
        Assert.Equal(before, reread.QueryDriveTrend("C:").Count);

        vm.Apply(snapshot);
        Assert.Equal("scan cost line", vm.ScanCost);
        Assert.NotEmpty(vm.DriveTrends);
    }

    [Fact]
    public void CollectNow_ProducerFailure_FallsBackWithoutThrowing()
    {
        var badStore = new PerformanceViewModel(
            () => throw new IOException("disk gone"), () => throw new InvalidOperationException("boom"));
        var snapshot = badStore.CollectNow([]);

        Assert.Equal(PerformanceExtras.Default.ScanCost, snapshot.ScanCost);
        Assert.Empty(snapshot.DriveTrends);
        Assert.Equal(PerformanceExtras.Default.CrashTrend, snapshot.CrashTrend);
        Assert.NotNull(badStore.LastPersistError);
    }

    [Fact]
    public void Apply_SetsIoNow_FromLatestSample()
    {
        var vm = new PerformanceViewModel();
        var sample = new ResourceSample(DateTime.UtcNow, 1.0, 2.0, 12.4, 3.1);
        vm.Apply(new PerformanceViewModel.PerformanceSnapshot(
            [], [], string.Empty, string.Empty, string.Empty, null, string.Empty, [], [sample]));

        Assert.Equal("Read 12 MB · Wrote 3 MB", vm.IoNow);

        vm.Apply(new PerformanceViewModel.PerformanceSnapshot(
            [], [], string.Empty, string.Empty, string.Empty, null, string.Empty, [], []));
        Assert.Equal("—", vm.IoNow);
    }
}
