using Sentinel.Engine.Inventory;
using Sentinel.Engine.Policy;
using Sentinel.Store;

namespace Sentinel.Tests;

// P22: scan-time classification, attribute flags, orphan caching,
// app grouping. Temp DBs/dirs only; never-list rule keeps verdicts
// machine-independent.
public sealed class InventoryClassifierTests : IDisposable
{
    private readonly string _dir;

    public InventoryClassifierTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "sentinel-p22c-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(_dir, recursive: true);
        }
        catch
        {
        }
    }

    private SentinelDb NewDb([System.Runtime.CompilerServices.CallerMemberName] string name = "")
    {
        return new SentinelDb(Path.Combine(_dir, name + ".db"));
    }

    [Fact]
    public void ComputeAttrFlags_MapsBits()
    {
        Assert.Equal(0, DiskInventoryScanner.ComputeAttrFlags(FileAttributes.Normal));
        Assert.Equal(FingerprintAttrs.Sparse,
            DiskInventoryScanner.ComputeAttrFlags(FileAttributes.SparseFile));
        Assert.Equal(FingerprintAttrs.Placeholder,
            DiskInventoryScanner.ComputeAttrFlags(FileAttributes.Offline));
        Assert.Equal(FingerprintAttrs.Sparse | FingerprintAttrs.Placeholder,
            DiskInventoryScanner.ComputeAttrFlags(
                FileAttributes.SparseFile | FileAttributes.Offline | FileAttributes.Archive));
    }

    [Fact]
    public async Task Scanner_ClassifiesAtScan_WhenClassifierSet()
    {
        string file = Path.Combine(_dir, "scan.txt");
        File.WriteAllText(file, "hello");
        using var db = NewDb();
        var scanner = new DiskInventoryScanner(db)
        {
            Classifier = new RiskClassifier([_dir]),
            ClassifyUtcNow = DateTime.UtcNow,
        };
        var outcome = await scanner.ProcessFileAsync(file, 1, CancellationToken.None);
        Assert.True(outcome.Counted);
        var row = db.GetFingerprint(file);
        Assert.NotNull(row);
        Assert.Equal("NEVER", row.Tier);
        Assert.Equal(1, row.ClassGen);
    }

    [Fact]
    public async Task Scanner_LeavesTierNull_WithoutClassifier()
    {
        string file = Path.Combine(_dir, "plain.txt");
        File.WriteAllText(file, "hello");
        using var db = NewDb();
        var scanner = new DiskInventoryScanner(db);
        await scanner.ProcessFileAsync(file, 1, CancellationToken.None);
        var row = db.GetFingerprint(file);
        Assert.NotNull(row);
        Assert.Null(row.Tier);
    }

    [Fact]
    public async Task Scanner_RecordsPlaceholderFlag()
    {
        string file = Path.Combine(_dir, "cloud.txt");
        File.WriteAllText(file, "hello");
        File.SetAttributes(file, File.GetAttributes(file) | FileAttributes.Offline);
        try
        {
            using var db = NewDb();
            var scanner = new DiskInventoryScanner(db);
            var outcome = await scanner.ProcessFileAsync(file, 1, CancellationToken.None);
            Assert.True(outcome.Counted);
            var row = db.GetFingerprint(file);
            Assert.NotNull(row);
            Assert.True((row.AttrFlags & FingerprintAttrs.Placeholder) != 0);
            Assert.Null(row.Hash);
        }
        finally
        {
            File.SetAttributes(file, File.GetAttributes(file) & ~FileAttributes.Offline);
        }
    }

    [Fact]
    public void FindEntry_LocationBeatsName_UnknownWhenNone()
    {
        var entries = new List<UninstallEntry>
        {
            new("Contoso Editor", @"C:\P22\Apps\Editor", null, null),
            new("Fabrikam Player", null, null, null),
        };
        var byLoc = OrphanHunter.FindEntry(@"C:\P22\Apps\Editor", entries);
        Assert.NotNull(byLoc);
        Assert.Equal("Contoso Editor", byLoc.DisplayName);
        var byName = OrphanHunter.FindEntry(@"C:\P22\Apps\FabrikamPlayer", entries);
        Assert.NotNull(byName);
        Assert.Equal("Fabrikam Player", byName.DisplayName);
        Assert.True(OrphanHunter.MatchesAnyEntry(@"C:\P22\Apps\Editor", entries));
        Assert.Null(OrphanHunter.FindEntry(@"C:\P22\Apps\StrangerThings", entries));
        Assert.False(OrphanHunter.MatchesAnyEntry(@"C:\P22\Apps\StrangerThings", entries));
    }

    [Fact]
    public void AppGrouper_GroupsKnownAndUnknown()
    {
        using var db = NewDb();
        db.UpsertFingerprint(@"C:\P22\Apps\Editor\a.dll", 100, 1, "h1", 1);
        db.UpsertFingerprint(@"C:\P22\Apps\Editor\b.dll", 200, 2, "h2", 1);
        db.UpsertFingerprint(@"C:\P22\Apps\Mystery\c.dll", 400, 3, "h3", 1);
        var entries = new List<UninstallEntry>
        {
            new("Contoso Editor", @"C:\P22\Apps\Editor", null, null),
        };
        var groups = AppGrouper.GroupApps(db, [@"C:\P22\Apps"], entries, CancellationToken.None);
        Assert.Equal(2, groups.Count);
        var known = groups.Single(g => g.Directory.EndsWith("Editor"));
        Assert.Equal("Contoso Editor", known.AppName);
        Assert.True(known.Known);
        Assert.Equal(2, known.Files);
        Assert.Equal(300, known.Bytes);
        var unknown = groups.Single(g => g.Directory.EndsWith("Mystery"));
        Assert.Equal("Unknown", unknown.AppName);
        Assert.False(unknown.Known);
        Assert.Equal(400, unknown.Bytes);
    }

    [Fact]
    public void EnsureClassified_FillsTiers_AndCachesOrphans()
    {
        using var db = NewDb();
        string keep = Path.Combine(_dir, "keep");
        Directory.CreateDirectory(keep);
        db.UpsertFingerprint(Path.Combine(keep, "a.tmp"), 10, 1, null, 1);
        db.UpsertFingerprint(Path.Combine(_dir, "b.tmp"), 20, 2, null, 1);
        var svc = new InventoryClassifier(db, [keep]);
        svc.EnsureClassified(DateTime.UtcNow, CancellationToken.None);
        Assert.Equal(0, db.CountUnclassified(0));
        var page = db.QueryInventoryPage(new InventoryQuery(Limit: 10));
        Assert.All(page.Rows, f => Assert.NotNull(f.Tier));
        Assert.NotNull(db.GetMeta("OrphanGen"));
        Assert.NotNull(db.GetMeta("NeverHash"));
        // Second run is a no-op: orphan table untouched, tiers kept.
        var before = db.QueryOrphanDirs(500, 0, out _);
        svc.EnsureClassified(DateTime.UtcNow, CancellationToken.None);
        var after = db.QueryOrphanDirs(500, 0, out _);
        Assert.Equal(before.Count, after.Count);
    }

    [Fact]
    public void EnsureClassified_NeverListChange_ReclassifiesAll()
    {
        using var db = NewDb();
        string keep = Path.Combine(_dir, "keep");
        Directory.CreateDirectory(keep);
        string file = Path.Combine(keep, "a.tmp");
        File.WriteAllText(file, "x");
        db.UpsertFingerprint(file, 10, DateTime.UtcNow.Ticks, null, 1);
        new InventoryClassifier(db, []).EnsureClassified(DateTime.UtcNow, CancellationToken.None);
        string? before = db.GetFingerprint(file)?.Tier;
        Assert.NotNull(before);
        Assert.NotEqual("NEVER", before);
        new InventoryClassifier(db, [keep]).EnsureClassified(DateTime.UtcNow, CancellationToken.None);
        Assert.Equal("NEVER", db.GetFingerprint(file)?.Tier);
    }

    [Fact]
    public void EnsureClassified_StatChange_RefillsOneRow()
    {
        using var db = NewDb();
        db.UpsertFingerprint(@"X:\P22\a.tmp", 10, 100, null, 1);
        new InventoryClassifier(db, []).EnsureClassified(DateTime.UtcNow, CancellationToken.None);
        Assert.Equal(0, db.CountUnclassified(0));
        db.UpsertFingerprint(@"X:\P22\a.tmp", 11, 100, null, 2);
        Assert.Equal(1, db.CountUnclassified(0));
        new InventoryClassifier(db, []).EnsureClassified(DateTime.UtcNow, CancellationToken.None);
        Assert.Equal(0, db.CountUnclassified(0));
        Assert.NotNull(db.GetFingerprint(@"X:\P22\a.tmp")?.Tier);
    }
}
