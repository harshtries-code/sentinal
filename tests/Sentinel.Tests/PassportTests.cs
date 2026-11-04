using Microsoft.Data.Sqlite;
using Sentinel.App.ViewModels;
using Sentinel.Engine.CrashDoctor;
using Sentinel.Engine.SystemInventory;
using Sentinel.Store;

namespace Sentinel.Tests;

// P26: Passport persistence + distinct stores. Run history,
// crashes/trends, device history, the rollback blocklist, and
// keeper decisions survive restarts in their own file; the
// rebuildable cache lives separately; schemas migrate atomically.
public sealed class PassportTests : IDisposable
{
    private readonly string _dir;

    public PassportTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "sentinel-p26-" + Guid.NewGuid().ToString("N"));
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

    private string Anchor(string name = "store.db") => Path.Combine(_dir, name);

    private static int ReadUserVersion(string path)
    {
        using var conn = new SqliteConnection($"Data Source={path};Mode=ReadOnly;Pooling=false");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "PRAGMA user_version;";
        return Convert.ToInt32(cmd.ExecuteScalar());
    }

    private static void Exec(string path, string sql)
    {
        using var conn = new SqliteConnection($"Data Source={path};Pooling=false");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    [Fact]
    public void RunsPersist_AcrossReopen_InPassportFile()
    {
        string anchor = Anchor();
        using (var store = new SentinelDb(anchor))
        {
            long id = store.BeginRun(_dir, 1, "Balanced");
            store.EndRun(id, 10, 5000, 2, 1200, "Completed", null, 1);
            store.RecordAbortedRun(_dir, 2, 3, 300, 0, 50, "Cancelled", null, "Eco");
        }

        // The anchor is a layout root: the pair holds the data.
        Assert.False(File.Exists(anchor));
        string passport = StoreLayout.DerivePassportPath(anchor);
        string cache = StoreLayout.DeriveFingerprintPath(anchor);
        Assert.True(File.Exists(passport));
        Assert.True(File.Exists(cache));

        using (var reopened = new SentinelDb(anchor))
        {
            var runs = reopened.ListRuns(10);
            Assert.Equal(2, runs.Count);
            Assert.Equal("Cancelled", runs[0].Status);
            Assert.Equal("Completed", runs[1].Status);
            Assert.Equal(10, runs[1].FilesSeen);
            Assert.Equal(2, reopened.GetMaxGeneration());
            var run = reopened.GetRun(runs[1].Id);
            Assert.NotNull(run);
            Assert.Equal("Balanced", run.Mode);
        }
    }

    [Fact]
    public void FindingsResolvable_AfterReopen()
    {
        string agent = Path.Combine(_dir, "agent.db");
        using (var store = new AgentStore(agent))
        {
            store.UpsertFinding(
                "f1", "inv1", 3, "Confirmed", "disk filled by logs",
                "log growth", "[\"ev-log-1\",\"ev-log-2\"]",
                "none", "review logs");
        }

        using (var reopened = new AgentStore(agent))
        {
            var findings = reopened.GetFindings("inv1");
            var finding = Assert.Single(findings);
            Assert.Equal("f1", finding.Id);
            Assert.Equal(3, finding.Revision);
            Assert.Equal("[\"ev-log-1\",\"ev-log-2\"]", finding.EvidenceIdsJson);
        }
    }

    [Fact]
    public void CrashSnapshots_Trend_AcrossRestart_Idempotent()
    {
        string anchor = Anchor();
        DateTime now = DateTime.UtcNow;
        var rows = new List<CrashSnapshot>
        {
            new("System:101", now.AddDays(-1).ToString("O"), now.ToString("O"),
                "System/Microsoft-Windows-Kernel-Power", 41, null, null, "Crash"),
            new("System:102", now.AddDays(-2).ToString("O"), now.ToString("O"),
                "System/EventLog", 6008, null, null, "Crash"),
            new("System:103", now.AddDays(-9).ToString("O"), now.ToString("O"),
                "System/disk", 153, null, null, "Disk warning"),
        };
        using (var store = new SentinelDb(anchor))
        {
            store.Passport.RecordCrashSnapshots(rows);
            // Re-collecting the same events overwrites, never appends.
            store.Passport.RecordCrashSnapshots(rows);
        }

        using (var reopened = new SentinelDb(anchor))
        {
            Assert.Equal(3, reopened.Passport.QueryCrashSnapshots().Count);
            var trend = reopened.Passport.QueryCrashTrend(2, now);
            Assert.Equal(2, trend.Count);
            Assert.Equal(1, trend[0].Total); // 8-14 days ago
            Assert.Equal(2, trend[1].Total); // 0-7 days ago
        }
    }

    [Fact]
    public void DeviceHistory_AppendsOnChange_Only()
    {
        string anchor = Anchor();
        var first = new List<(string, string, int, string, string?)>
        {
            ("DEV1", "Widget", 28, "Drivers not installed", "1.0"),
        };
        using (var store = new SentinelDb(anchor))
        {
            Assert.Equal(1, store.Passport.RecordDeviceStates(first));
            Assert.Equal(0, store.Passport.RecordDeviceStates(first));
            var changed = new List<(string, string, int, string, string?)>
            {
                ("DEV1", "Widget", 0, "Working", "2.0"),
            };
            Assert.Equal(1, store.Passport.RecordDeviceStates(changed));
        }

        using (var reopened = new SentinelDb(anchor))
        {
            var history = reopened.Passport.QueryDeviceHistory("DEV1");
            Assert.Equal(2, history.Count);
            Assert.Equal(0, history[0].Problem);
            Assert.Equal(28, history[1].Problem);
            var latest = Assert.Single(reopened.Passport.QueryDeviceLatest());
            Assert.Equal("DEV1", latest.InstanceId);
            Assert.Equal("2.0", latest.DriverVersion);
        }
    }

    [Fact]
    public void Blocklist_Lookup_RoundTrip()
    {
        string anchor = Anchor();
        using (var store = new SentinelDb(anchor))
        {
            Assert.False(store.Passport.IsBlockedDriver("DEV9", "3.1"));
            store.Passport.AddBlockedDriver("DEV9", "3.1", "WindowsUpdate", "rolled back: blank screen");
        }

        using (var reopened = new SentinelDb(anchor))
        {
            Assert.True(reopened.Passport.IsBlockedDriver("DEV9", "3.1"));
            Assert.False(reopened.Passport.IsBlockedDriver("DEV9", "3.2"));
            var blocked = Assert.Single(reopened.Passport.QueryBlockedDrivers());
            Assert.Equal("WindowsUpdate", blocked.Source);
            Assert.Equal("rolled back: blank screen", blocked.Reason);
            Assert.True(reopened.Passport.RemoveBlockedDriver("DEV9", "3.1"));
            Assert.False(reopened.Passport.RemoveBlockedDriver("DEV9", "3.1"));
            Assert.False(reopened.Passport.IsBlockedDriver("DEV9", "3.1"));
        }
    }

    [Fact]
    public void Blocklist_V2Migrates_SourceDefaultsUnknown()
    {
        // A v2 file: old 4-column blocklist + one pre-D42 row.
        string passport = Anchor("v2.db");
        Exec(passport, """
            CREATE TABLE DriverBlocklist(
                DeviceKey TEXT NOT NULL,
                BadVersion TEXT NOT NULL,
                Reason TEXT NOT NULL DEFAULT '',
                AddedUtc TEXT NOT NULL,
                PRIMARY KEY(DeviceKey, BadVersion));
            INSERT INTO DriverBlocklist(DeviceKey, BadVersion, Reason, AddedUtc)
            VALUES ('DEV1', '1.0', 'old', '2026-01-01T00:00:00Z');
            PRAGMA user_version = 2;
            """);

        using (var db = new PassportDb(passport))
        {
            var row = Assert.Single(db.QueryBlockedDrivers());
            Assert.Equal("unknown", row.Source);
            Assert.Equal("DEV1", row.DeviceKey);
            db.AddBlockedDriver("DEV2", "2.0", "OemCatalogue", "new");
            Assert.Equal(2, db.QueryBlockedDrivers().Count);
        }

        Assert.Equal(PassportDb.SchemaVersion, ReadUserVersion(passport));
    }

    [Fact]
    public void KeeperDecisions_Overwrite_BySetHash()
    {
        string anchor = Anchor();
        using (var store = new SentinelDb(anchor))
        {
            store.Passport.RecordKeeperDecision("h1", @"C:\a\f.dat", "app-owned install");
            store.Passport.RecordKeeperDecision("h1", @"C:\b\f.dat", "re-reasoned: newer");
        }

        using (var reopened = new SentinelDb(anchor))
        {
            var decision = reopened.Passport.QueryKeeperDecision("h1");
            Assert.NotNull(decision);
            Assert.Equal(@"C:\b\f.dat", decision.KeeperPath);
            Assert.Contains("re-reasoned", decision.Rationale);
            Assert.Null(reopened.Passport.QueryKeeperDecision("missing"));
        }
    }

    [Fact]
    public void CacheRebuild_KeepsPassport_Rows()
    {
        string anchor = Anchor();
        using (var store = new SentinelDb(anchor))
        {
            long id = store.BeginRun(_dir, 1, "Balanced");
            store.EndRun(id, 1, 100, 0, 10, "Completed", null, 0);
            store.UpsertFingerprint(Path.Combine(_dir, "a.dat"), 100, DateTime.UtcNow.Ticks, null, 1);
        }

        var outcome = StoreRecovery.TryRebuildFingerprintCache(anchor);
        Assert.True(outcome.Success);
        Assert.Contains("history kept", outcome.Detail);
        Assert.Contains("Passport history kept (1 runs)", outcome.Detail);

        using (var store = new SentinelDb(anchor))
        {
            Assert.Equal(0, store.CountFingerprints());
            Assert.Single(store.ListRuns(10));
        }
    }

    [Fact]
    public void CorruptCache_Quarantines_PassportUntouched()
    {
        string anchor = Anchor();
        using (var store = new SentinelDb(anchor))
        {
            long id = store.BeginRun(_dir, 1, "Balanced");
            store.EndRun(id, 1, 100, 0, 10, "Completed", null, 0);
            store.UpsertFingerprint(Path.Combine(_dir, "a.dat"), 100, DateTime.UtcNow.Ticks, null, 1);
        }

        string cache = StoreLayout.DeriveFingerprintPath(anchor);
        string passport = StoreLayout.DerivePassportPath(anchor);
        SqliteConnection.ClearAllPools();
        byte[] passportBefore = File.ReadAllBytes(passport);
        byte[] garbage = [0xDE, 0xAD, 0xBE, 0xEF];
        SqliteConnection.ClearAllPools();
        File.WriteAllBytes(cache, garbage);

        var outcome = StoreRecovery.TryRebuildFingerprintCache(anchor);
        Assert.True(outcome.Success);
        Assert.Equal(RecoveryKind.QuarantinedAndRebuilt, outcome.Kind);
        Assert.Contains("quarantine", outcome.Detail);
        Assert.Contains("Passport history kept (1 runs)", outcome.Detail);
        Assert.NotNull(outcome.QuarantinePath);
        Assert.Equal(garbage, File.ReadAllBytes(outcome.QuarantinePath));
        SqliteConnection.ClearAllPools();
        Assert.Equal(passportBefore, File.ReadAllBytes(passport));

        using (var store = new SentinelDb(anchor))
        {
            Assert.Equal(0, store.CountFingerprints());
            Assert.Single(store.ListRuns(10));
        }
    }

    [Fact]
    public void CorruptPassport_Recovers_Fresh_WithLoudLoss()
    {
        string anchor = Anchor();
        using (var store = new SentinelDb(anchor))
        {
            long id = store.BeginRun(_dir, 1, "Balanced");
            store.EndRun(id, 1, 100, 0, 10, "Completed", null, 0);
        }

        string passport = StoreLayout.DerivePassportPath(anchor);
        byte[] garbage = [0xBA, 0xAD, 0xF0, 0x0D];
        SqliteConnection.ClearAllPools();
        File.WriteAllBytes(passport, garbage);

        var outcome = StoreRecovery.TryRecoverPassport(anchor);
        Assert.True(outcome.Success);
        Assert.Equal(RecoveryKind.QuarantinedAndRebuilt, outcome.Kind);
        Assert.Contains("NOT in the app anymore", outcome.Detail);
        Assert.NotNull(outcome.QuarantinePath);
        Assert.Equal(garbage, File.ReadAllBytes(outcome.QuarantinePath));

        using (var store = new SentinelDb(anchor))
        {
            Assert.Empty(store.ListRuns(10));
        }
    }

    [Fact]
    public void OldSchema_Migrates_WithData_Passport()
    {
        string passport = Path.Combine(_dir, "old-passport.db");
        Exec(passport, """
            CREATE TABLE ScanRuns(
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                StartedUtc TEXT NOT NULL,
                Root TEXT NOT NULL,
                Generation INTEGER NOT NULL,
                FilesSeen INTEGER NOT NULL DEFAULT 0,
                BytesSeen INTEGER NOT NULL DEFAULT 0,
                FilesHashed INTEGER NOT NULL DEFAULT 0,
                DurationMs INTEGER NOT NULL DEFAULT 0);
            INSERT INTO ScanRuns(StartedUtc, Root, Generation, FilesSeen)
            VALUES ('2026-01-01T00:00:00Z', 'C:\\', 7, 42);
            PRAGMA user_version = 0;
            """);

        using (var db = new PassportDb(passport))
        {
            var runs = db.ListRuns(10);
            var run = Assert.Single(runs);
            Assert.Equal(7, run.Generation);
            Assert.Equal(42, run.FilesSeen);
            Assert.Equal("Running", run.Status);
        }

        Assert.Equal(PassportDb.SchemaVersion, ReadUserVersion(passport));
    }

    [Fact]
    public void OldSchema_Migrates_WithData_Fingerprints()
    {
        string cache = Path.Combine(_dir, "old-fp.db");
        Exec(cache, """
            CREATE TABLE Fingerprints(
                Path TEXT PRIMARY KEY,
                Size INTEGER NOT NULL,
                MTimeUtcTicks INTEGER NOT NULL,
                Hash TEXT NULL,
                LastSeenGeneration INTEGER NOT NULL);
            INSERT INTO Fingerprints(Path, Size, MTimeUtcTicks, Hash, LastSeenGeneration)
            VALUES ('C:\f.dat', 9, 1, NULL, 3);
            PRAGMA user_version = 0;
            """);

        using (var db = new FingerprintDb(cache))
        {
            var fp = db.GetFingerprint(@"C:\f.dat");
            Assert.NotNull(fp);
            Assert.Equal(9, fp.Size);
            Assert.Null(fp.Tier);
            Assert.Equal(0, fp.AttrFlags);
        }

        Assert.Equal(FingerprintDb.SchemaVersion, ReadUserVersion(cache));
    }

    [Fact]
    public void InterruptedMigration_Converges_Passport()
    {
        // Version 0 with a PARTIAL schema (as if an older migrator
        // died mid-apply): reopen must converge, keep the row.
        string passport = Path.Combine(_dir, "partial-passport.db");
        Exec(passport, """
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
            INSERT INTO ScanRuns(StartedUtc, Root, Generation, Status)
            VALUES ('2026-01-01T00:00:00Z', 'C:\\', 5, 'Completed');
            PRAGMA user_version = 0;
            """);

        using (var db = new PassportDb(passport))
        {
            Assert.Single(db.ListRuns(10));
            // New tables exist and accept writes.
            db.RecordKeeperDecision("h", @"C:\k", "why");
            Assert.NotNull(db.QueryKeeperDecision("h"));
        }

        Assert.Equal(PassportDb.SchemaVersion, ReadUserVersion(passport));
    }

    [Fact]
    public void InterruptedMigration_Converges_Fingerprints()
    {
        string cache = Path.Combine(_dir, "partial-fp.db");
        Exec(cache, """
            CREATE TABLE Fingerprints(
                Path TEXT PRIMARY KEY,
                Size INTEGER NOT NULL,
                MTimeUtcTicks INTEGER NOT NULL,
                Hash TEXT NULL,
                LastSeenGeneration INTEGER NOT NULL,
                Tier TEXT NULL,
                Regrowth TEXT NULL,
                AttrFlags INTEGER NOT NULL DEFAULT 0,
                ClassGen INTEGER NOT NULL DEFAULT 0);
            INSERT INTO Fingerprints(Path, Size, MTimeUtcTicks, Hash, LastSeenGeneration)
            VALUES ('C:\g.dat', 3, 1, NULL, 2);
            PRAGMA user_version = 0;
            """);

        using (var db = new FingerprintDb(cache))
        {
            Assert.NotNull(db.GetFingerprint(@"C:\g.dat"));
            db.SetMeta("k", "v");
            Assert.Equal("v", db.GetMeta("k"));
        }

        Assert.Equal(FingerprintDb.SchemaVersion, ReadUserVersion(cache));
    }

    [Fact]
    public void NewerSchema_RefusesToOpen()
    {
        string passport = Path.Combine(_dir, "new-passport.db");
        using (var db = new PassportDb(passport))
        {
        }

        Exec(passport, "PRAGMA user_version = 99;");
        Assert.Throws<InvalidOperationException>(() => new PassportDb(passport));

        string cache = Path.Combine(_dir, "new-fp.db");
        using (var db = new FingerprintDb(cache))
        {
        }

        Exec(cache, "PRAGMA user_version = 99;");
        Assert.Throws<InvalidOperationException>(() => new FingerprintDb(cache));
    }

    [Fact]
    public void SimultaneousReaders_Succeed()
    {
        string anchor = Anchor();
        using (var store = new SentinelDb(anchor))
        {
            long id = store.BeginRun(_dir, 1, "Balanced");
            store.EndRun(id, 1, 100, 0, 10, "Completed", null, 0);
            store.UpsertFingerprint(Path.Combine(_dir, "a.dat"), 100, DateTime.UtcNow.Ticks, null, 1);
        }

        var errors = new System.Collections.Concurrent.ConcurrentBag<Exception>();
        System.Threading.Tasks.Parallel.For(0, 32, _ =>
        {
            try
            {
                using var store = new SentinelDb(anchor);
                Assert.Single(store.ListRuns(10));
                Assert.Equal(1, store.CountFingerprints());
            }
            catch (Exception ex)
            {
                errors.Add(ex);
            }
        });
        Assert.Empty(errors);
    }

    [Fact]
    public void LegacySplit_Migrates_And_KeepsBackup()
    {
        string anchor = Anchor("legacy.db");
        byte[] legacyBytes;
        using (var conn = new SqliteConnection($"Data Source={anchor};Pooling=false"))
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
                    DurationMs INTEGER NOT NULL DEFAULT 0);
                INSERT INTO ScanRuns(StartedUtc, Root, Generation, FilesSeen)
                VALUES ('2026-01-01T00:00:00Z', 'C:\\', 4, 11);
                CREATE TABLE Fingerprints(
                    Path TEXT PRIMARY KEY,
                    Size INTEGER NOT NULL,
                    MTimeUtcTicks INTEGER NOT NULL,
                    Hash TEXT NULL,
                    LastSeenGeneration INTEGER NOT NULL);
                INSERT INTO Fingerprints(Path, Size, MTimeUtcTicks, Hash, LastSeenGeneration)
                VALUES ('C:\old.dat', 44, 1, NULL, 4);
                CREATE TABLE Meta(Key TEXT PRIMARY KEY, Value TEXT NOT NULL);
                INSERT INTO Meta(Key, Value) VALUES ('OrphanGen', '4');
                PRAGMA user_version = 0;
                """;
            cmd.ExecuteNonQuery();
        }

        legacyBytes = File.ReadAllBytes(anchor);

        using (var store = new SentinelDb(anchor))
        {
            var run = Assert.Single(store.ListRuns(10));
            Assert.Equal(4, run.Generation);
            Assert.Equal(11, run.FilesSeen);
            Assert.Equal("Completed", run.Status);
            var fp = store.GetFingerprint(@"C:\old.dat");
            Assert.NotNull(fp);
            Assert.Equal(44, fp.Size);
            Assert.Equal("4", store.GetMeta("OrphanGen"));
        }

        // Legacy file renamed to a backup, bytes preserved, data split.
        Assert.False(File.Exists(anchor));
        var backups = Directory.GetFiles(_dir, "legacy-legacy-*.db");
        var backup = Assert.Single(backups);
        Assert.Equal(legacyBytes, File.ReadAllBytes(backup));
        Assert.True(File.Exists(StoreLayout.DerivePassportPath(anchor)));
        Assert.True(File.Exists(StoreLayout.DeriveFingerprintPath(anchor)));

        // Second open is a plain open (idempotent, no re-migration).
        using (var again = new SentinelDb(anchor))
        {
            Assert.Single(again.ListRuns(10));
            Assert.Equal(1, again.CountFingerprints());
        }

        Assert.Single(Directory.GetFiles(_dir, "legacy-legacy-*.db"));
    }

    [Fact]
    public void Crashes_Apply_PersistsSnapshots()
    {
        string passport = Path.Combine(_dir, "crash-passport.db");
        var vm = new CrashesViewModel(() => new PassportDb(passport));
        DateTime now = DateTime.UtcNow;
        var rows = new List<CrashesViewModel.CrashRow>
        {
            new("today", CrashesViewModel.TypeCrash, "power loss", 41, 0,
                new TargetedEventRecord("System", 9001, 41, "Critical", now, "Kernel-Power", "m", [])),
        };
        var dumps = new List<MinidumpReport>
        {
            new("012626-1.dmp", 1000, now, 0x9Fu, "DRIVER_POWER_STATE_FAILURE", "usb.sys", null, "Analyzed", null),
        };
        vm.Apply(new CrashesViewModel.CrashesSnapshot("s", "c", rows, [], "", "", dumps));

        Assert.Null(vm.LastPersistError);
        using (var db = new PassportDb(passport))
        {
            var snaps = db.QueryCrashSnapshots();
            Assert.Equal(2, snaps.Count);
            Assert.Contains(snaps, s => s.Key == "System:9001" && s.Bucket == CrashesViewModel.TypeCrash);
            var dump = Assert.Single(snaps, s => s.Source == "Minidump");
            Assert.Equal("0x9F", dump.Code);
            Assert.Equal("usb.sys", dump.Module);
        }
    }

    [Fact]
    public void Drivers_Apply_PersistsHistory_AndRecovery()
    {
        string passport = Path.Combine(_dir, "dev-passport.db");
        var vm = new DriversViewModel(() => new PassportDb(passport));
        var problems = new List<DriverProblemRow>
        {
            new("Widget", "Drivers not installed", "Code 28", false, "DEV1"),
        };
        var drivers = new List<DriverRow>
        {
            new("Widget", "1.0", "Vendor", "Degraded"),
        };
        vm.Apply(new DriversViewModel.DriversSnapshot("s", "c", problems, drivers, [], DateTime.UtcNow, ""));
        Assert.Null(vm.LastPersistError);

        using (var db = new PassportDb(passport))
        {
            var history = db.QueryDeviceHistory("DEV1");
            var row = Assert.Single(history);
            Assert.Equal(28, row.Problem);
            Assert.Equal("1.0", row.DriverVersion);
        }

        // Same state again: zero new rows.
        vm.Apply(new DriversViewModel.DriversSnapshot("s", "c", problems, drivers, [], DateTime.UtcNow, ""));
        using (var db = new PassportDb(passport))
        {
            Assert.Single(db.QueryDeviceHistory("DEV1"));
        }

        // Problem gone: a Working row records the recovery.
        vm.Apply(new DriversViewModel.DriversSnapshot(
            "s", "c", [], drivers, [], DateTime.UtcNow, ""));
        using (var db = new PassportDb(passport))
        {
            var history = db.QueryDeviceHistory("DEV1");
            Assert.Equal(2, history.Count);
            Assert.Equal(0, history[0].Problem);
            Assert.Equal("Working", history[0].Status);
        }
    }

    [Fact]
    public void ParseProblemCode_Matrix()
    {
        Assert.Equal(45, DriversViewModel.ParseProblemCode("Code 45"));
        Assert.Equal(0, DriversViewModel.ParseProblemCode("Code 0"));
        Assert.Equal(-1, DriversViewModel.ParseProblemCode("bogus"));
        Assert.Equal(-1, DriversViewModel.ParseProblemCode(""));
    }

    [Fact]
    public void DuplicatesPage_PersistsKeeperDecision()
    {
        string anchor = Anchor("keeper.db");
        string keep = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "sentinel-p26-" + Guid.NewGuid().ToString("N"), "keep.dat");
        string spare = Path.Combine(_dir, "spare.dat");
        using (var store = new SentinelDb(anchor))
        {
            store.UpsertFingerprint(keep, 100, DateTime.UtcNow.Ticks, "hash-k", 1);
            store.UpsertFingerprint(spare, 100, DateTime.UtcNow.Ticks, "hash-k", 1);
        }

        var vm = new CleanerViewModel(() => new SentinelDb(anchor), () => []);
        vm.Refresh();
        vm.SelectedChip = "Duplicates";
        Assert.NotEmpty(vm.VisibleRows);

        using (var db = new PassportDb(StoreLayout.DerivePassportPath(anchor)))
        {
            var decision = db.QueryKeeperDecision("hash-k");
            Assert.NotNull(decision);
            Assert.Equal(keep, decision.KeeperPath);
            Assert.NotEmpty(decision.Rationale);
        }
    }
}
