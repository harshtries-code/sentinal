using Sentinel.App.Services;
using Sentinel.App.ViewModels;
using Sentinel.Store;

namespace Sentinel.Tests;

// A08: cache recovery preserves history. Fingerprint rebuild is
// separated from any investigation/audit wipe (N63 owns the
// explicit full wipe): healthy stores keep run history, corrupt
// stores are quarantined (never deleted), and a failed rebuild
// keeps its error instead of clearing it silently.
public sealed class StoreRecoveryTests : IDisposable
{
    private readonly string _dir;

    public StoreRecoveryTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "sentinel-a08-" + Guid.NewGuid().ToString("N"));
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

    private string DbPath(string name = "scan.db") => Path.Combine(_dir, name);

    private MainViewModel Main(string dbPath) =>
        new(() => new SentinelDb(dbPath), new ImmediateDispatcher(), dbPath);

    [Fact]
    public void HealthyDb_Rebuild_KeepsRunHistory_AgentUntouched()
    {
        string db = DbPath();
        string agent = DbPath("agent.db");
        using (var store = new SentinelDb(db))
        {
            long id = store.BeginRun(_dir, 1, "Balanced");
            store.EndRun(id, 2, 300, 0, 1000, "Completed", null, 0);
            long id2 = store.BeginRun(_dir, 2, "Balanced");
            store.EndRun(id2, 1, 100, 0, 500, "Completed", null, 1);
            store.UpsertFingerprint(Path.Combine(_dir, "a.dat"), 100, DateTime.UtcNow.Ticks, null, 2);
            store.UpsertFingerprint(Path.Combine(_dir, "b.dat"), 200, DateTime.UtcNow.Ticks, null, 2);
        }

        File.WriteAllBytes(agent, [1, 2, 3, 4]);
        byte[] agentBefore = File.ReadAllBytes(agent);

        var main = Main(db);
        Assert.Null(main.DbError);
        main.RebuildDataCommand.Execute(null);

        Assert.Null(main.DbError);
        Assert.Contains("history kept", main.LastRecoveryNote);
        using (var store = new SentinelDb(db))
        {
            Assert.Equal(0, store.CountFingerprints());
            Assert.Equal(2, store.ListRuns(10).Count);
        }

        // The investigation store is a different life: rebuild
        // never touches it (explicit wipe is N63's contract).
        Assert.Equal(agentBefore, File.ReadAllBytes(agent));
    }

    [Fact]
    public void CorruptDb_Quarantined_FreshMade_AgentUntouched()
    {
        string db = DbPath();
        string agent = DbPath("agent.db");
        byte[] garbage = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11];
        byte[] walGarbage = [0x5A, 0xA5, 0x5A, 0xFF];
        File.WriteAllBytes(db, garbage);
        File.WriteAllBytes(db + "-wal", walGarbage);
        File.WriteAllBytes(agent, [9, 9, 9]);
        byte[] agentBefore = File.ReadAllBytes(agent);

        var main = Main(db);
        Assert.Contains("corrupt", main.DbError);
        main.RebuildDataCommand.Execute(null);

        Assert.Null(main.DbError);
        Assert.Contains("quarantine", main.LastRecoveryNote);
        string quarantine = Path.Combine(_dir, "quarantine");
        Assert.True(Directory.Exists(quarantine));
        var kept = Directory.GetFiles(quarantine);
        // The corrupt store AND its WAL sidecar survive
        // byte-for-byte, moved aside — nothing was deleted.
        // (SQLite may add an empty -shm during probing; it rides
        // along, harmless.)
        Assert.Contains(kept, f => File.ReadAllBytes(f).SequenceEqual(garbage));
        Assert.Contains(kept, f => File.ReadAllBytes(f).SequenceEqual(walGarbage));
        Assert.False(File.Exists(db + "-wal"));
        // A fresh working store stands in its place.
        using (var store = new SentinelDb(db))
        {
            Assert.Equal(0, store.CountFingerprints());
            Assert.Empty(store.ListRuns(10));
        }

        Assert.Equal(agentBefore, File.ReadAllBytes(agent));
    }

    [Fact]
    public void OpenDb_Rebuild_Succeeds()
    {
        string db = DbPath();
        using (var store = new SentinelDb(db))
        {
            long id = store.BeginRun(_dir, 1, "Balanced");
            store.EndRun(id, 1, 100, 0, 500, "Completed", null, 0);
            store.UpsertFingerprint(Path.Combine(_dir, "a.dat"), 100, DateTime.UtcNow.Ticks, null, 1);
        }

        // A second open handle (a page mid-read, a running scan)
        // must not break the SQL-path rebuild.
        using var held = new SentinelDb(db);
        var main = Main(db);
        main.RebuildDataCommand.Execute(null);

        Assert.Null(main.DbError);
        using var verify = new SentinelDb(db);
        Assert.Equal(0, verify.CountFingerprints());
        Assert.Single(verify.ListRuns(10));
    }

    [Fact]
    public void LockedCorruptDb_Failure_KeepsError_NothingDeleted()
    {
        string db = DbPath();
        byte[] garbage = [0xBA, 0xAD, 0xF0, 0x0D];
        File.WriteAllBytes(db, garbage);

        var main = Main(db);
        Assert.Contains("corrupt", main.DbError);
        // Exclusive OS lock: quarantine cannot move the file, so
        // the rebuild must fail WITHOUT deleting or clearing.
        using (var locked = new FileStream(db, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            Assert.NotNull(locked);
            main.RebuildDataCommand.Execute(null);
        }

        Assert.NotNull(main.DbError);
        Assert.Contains("could not", main.DbError);
        Assert.True(File.Exists(db));
        Assert.Equal(garbage, File.ReadAllBytes(db));
        string quarantine = Path.Combine(_dir, "quarantine");
        Assert.False(Directory.Exists(quarantine)
            && Directory.GetFiles(quarantine).Length > 0);
    }

    [Fact]
    public void InterruptedRebuild_Recovers_NextRun()
    {
        // Crash between quarantine and recreate: an older
        // quarantine set exists, the main store is missing. The
        // next rebuild recreates fresh WITHOUT touching the kept
        // set (unique names, no overwrite).
        string db = DbPath();
        string quarantine = Path.Combine(_dir, "quarantine");
        Directory.CreateDirectory(quarantine);
        string kept = Path.Combine(quarantine, "scan-20240101-000000.db");
        File.WriteAllBytes(kept, [7, 7, 7]);

        var main = Main(db);
        main.RebuildDataCommand.Execute(null);

        Assert.Null(main.DbError);
        // P26: the anchor is a layout root now; the fresh pair
        // stands in its place (same intent: working store remade).
        Assert.True(File.Exists(StoreLayout.DerivePassportPath(db)));
        Assert.True(File.Exists(StoreLayout.DeriveFingerprintPath(db)));
        using (var store = new SentinelDb(db))
        {
            Assert.Empty(store.ListRuns(10));
        }

        Assert.True(File.Exists(kept));
        Assert.Equal([7, 7, 7], File.ReadAllBytes(kept));
    }

    [Fact]
    public void StoreRecovery_MissingFile_CreatesFresh()
    {
        string db = DbPath("fresh.db");
        var outcome = StoreRecovery.TryRebuildFingerprintCache(db);

        Assert.True(outcome.Success);
        Assert.Contains("fresh", outcome.Detail, StringComparison.OrdinalIgnoreCase);
        using var store = new SentinelDb(db);
        Assert.Empty(store.ListRuns(10));
    }
}
