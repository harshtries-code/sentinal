using Sentinel.Store;

namespace Sentinel.Tests;

// P22: paged full-inventory queries, groupings, duplicate sets,
// attribute stats, classification write-back. Temp DBs only.
public sealed class InventoryQueryTests : IDisposable
{
    private readonly string _dir;

    public InventoryQueryTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "sentinel-p22-" + Guid.NewGuid().ToString("N"));
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

    private static void Seed(SentinelDb db)
    {
        // 12 rows across tiers/sizes/extensions/names/dirs.
        var rows = new (string Path, long Size, string? Hash, string Tier, int Flags)[]
        {
            (@"C:\W\a.log", 100, "h1", "SAFE", 0),
            (@"C:\W\b.LOG", 200, "h1", "SAFE", 0),
            (@"C:\W\sub\c.tmp", 300, null, "REVIEW", 0),
            (@"C:\W\sub\d.dat", 400, "h2", "NEVER", 1),
            (@"C:\P\e.log", 500, "h2", "NEVER", 2),
            (@"C:\P\f.txt", 600, "h3", "SAFE", 0),
            (@"C:\P\f2.txt", 700, "h3", "REVIEW", 0),
            (@"C:\U\g.LOG", 800, "h4", "NEVER", 0),
            (@"C:\U\100%.log", 900, null, "REVIEW", 0),
            (@"C:\U\under_score.txt", 1000, "h5", "SAFE", 3),
            (@"C:\U\sub\deep\h.bin", 1100, "h5", "SAFE", 0),
            (@"C:\U\sub\i.bin", 1200, "h6", "REVIEW", 0),
        };
        int i = 0;
        foreach (var r in rows)
        {
            db.UpsertFingerprint(r.Path, r.Size, 1000 + i, r.Hash, 7, r.Flags,
                r.Tier, null, 7, hasTier: true);
            i++;
        }
    }

    [Fact]
    public void QueryPage_Unfiltered_PagesWithTotals()
    {
        using var db = NewDb();
        Seed(db);
        var p1 = db.QueryInventoryPage(new InventoryQuery(Limit: 5, Offset: 0));
        var p2 = db.QueryInventoryPage(new InventoryQuery(Limit: 5, Offset: 5));
        var p3 = db.QueryInventoryPage(new InventoryQuery(Limit: 5, Offset: 10));
        Assert.Equal(12, p1.TotalMatches);
        Assert.Equal(7800, p1.TotalBytes);
        Assert.Equal(7, p1.MaxGeneration);
        Assert.Equal(5, p1.Rows.Count);
        Assert.Equal(5, p2.Rows.Count);
        Assert.Equal(2, p3.Rows.Count);
        var all = p1.Rows.Concat(p2.Rows).Concat(p3.Rows).Select(f => f.Path).ToList();
        Assert.Equal(12, all.Distinct().Count());
        // Size desc, path tiebreak: deterministic order.
        Assert.True(p1.Rows[0].Size >= p1.Rows[4].Size);
    }

    [Fact]
    public void QueryPage_TierFilter()
    {
        using var db = NewDb();
        Seed(db);
        var safe = db.QueryInventoryPage(new InventoryQuery(Tier: "SAFE", Limit: 100));
        Assert.Equal(5, safe.TotalMatches);
        Assert.All(safe.Rows, f => Assert.Equal("SAFE", f.Tier));
        var never = db.QueryInventoryPage(new InventoryQuery(Tier: "NEVER", Limit: 100));
        Assert.Equal(3, never.TotalMatches);
    }

    [Fact]
    public void QueryPage_SizeRange()
    {
        using var db = NewDb();
        Seed(db);
        var page = db.QueryInventoryPage(new InventoryQuery(MinSize: 500, MaxSize: 900, Limit: 100));
        Assert.Equal(5, page.TotalMatches);
        Assert.All(page.Rows, f => Assert.InRange(f.Size, 500, 900));
    }

    [Fact]
    public void QueryPage_Extension_CaseAndDotInsensitive()
    {
        using var db = NewDb();
        Seed(db);
        var a = db.QueryInventoryPage(new InventoryQuery(Extension: ".log", Limit: 100));
        var b = db.QueryInventoryPage(new InventoryQuery(Extension: "LOG", Limit: 100));
        Assert.Equal(5, a.TotalMatches);
        Assert.Equal(5, b.TotalMatches);
    }

    [Fact]
    public void QueryPage_NameContains_EscapesWildcards()
    {
        using var db = NewDb();
        Seed(db);
        var pct = db.QueryInventoryPage(new InventoryQuery(NameContains: "100%", Limit: 100));
        Assert.Equal(1, pct.TotalMatches);
        var under = db.QueryInventoryPage(new InventoryQuery(NameContains: "under_score", Limit: 100));
        Assert.Equal(1, under.TotalMatches);
        var all = db.QueryInventoryPage(new InventoryQuery(NameContains: "C:\\", Limit: 100));
        Assert.Equal(12, all.TotalMatches);
    }

    [Fact]
    public void QueryPage_DirPrefix_Scoped()
    {
        using var db = NewDb();
        Seed(db);
        var w = db.QueryInventoryPage(new InventoryQuery(DirPrefixes: [@"C:\W"], Limit: 100));
        Assert.Equal(4, w.TotalMatches);
        var sub = db.QueryInventoryPage(new InventoryQuery(DirPrefixes: [@"C:\W\sub"], Limit: 100));
        Assert.Equal(2, sub.TotalMatches);
        var both = db.QueryInventoryPage(new InventoryQuery(DirPrefixes: [@"C:\W", @"C:\P"], Limit: 100));
        Assert.Equal(7, both.TotalMatches);
        var none = db.QueryInventoryPage(new InventoryQuery(DirPrefixes: [@"C:\Nope"], Limit: 100));
        Assert.Equal(0, none.TotalMatches);
        Assert.Equal(0, none.TotalBytes);
    }

    [Fact]
    public void QueryPage_HashMissing_And_Regrowing()
    {
        using var db = NewDb();
        Seed(db);
        db.SetClassification(@"C:\W\a.log", "SAFE", "Cache — returns soon.", 7);
        var missing = db.QueryInventoryPage(new InventoryQuery(HashMissingOnly: true, Limit: 100));
        Assert.Equal(2, missing.TotalMatches);
        var regrow = db.QueryInventoryPage(new InventoryQuery(RegrowingOnly: true, Limit: 100));
        Assert.Single(regrow.Rows);
    }

    [Fact]
    public void QueryPage_SortName_IsPathOrder()
    {
        using var db = NewDb();
        Seed(db);
        var page = db.QueryInventoryPage(new InventoryQuery(Sort: "name", Limit: 100));
        var paths = page.Rows.Select(f => f.Path).ToList();
        var sorted = paths.OrderBy(p => p, StringComparer.Ordinal).ToList();
        Assert.Equal(sorted, paths);
    }

    [Fact]
    public void CountGroupByTier_CoversAllRows()
    {
        using var db = NewDb();
        Seed(db);
        db.UpsertFingerprint(@"C:\N\new.bin", 50, 2000, null, 8);
        var groups = db.CountGroupByTier().ToDictionary(g => g.Tier);
        Assert.Equal(5, groups["SAFE"].Files);
        Assert.Equal(4, groups["REVIEW"].Files);
        Assert.Equal(3, groups["NEVER"].Files);
        Assert.Equal(1, groups[""].Files);
        Assert.Equal(13, groups.Values.Sum(g => g.Files));
        Assert.Equal(7850, groups.Values.Sum(g => g.Bytes));
    }

    [Fact]
    public void SumBuckets_PartitionsTotal_WithPriority()
    {
        using var db = NewDb();
        Seed(db);
        var buckets = db.SumBuckets(
            [("Win", @"C:\W"), ("Prog", @"C:\P")], "Other");
        Assert.Equal(4, buckets["Win"].Files);
        Assert.Equal(1000, buckets["Win"].Bytes);
        Assert.Equal(3, buckets["Prog"].Files);
        Assert.Equal(1800, buckets["Prog"].Bytes);
        Assert.Equal(5, buckets["Other"].Files);
        Assert.Equal(12, buckets.Values.Sum(v => v.Files));
        Assert.Equal(db.SumFingerprintBytes(), buckets.Values.Sum(v => v.Bytes));
        // Priority: overlapping prefixes credit the first bucket only.
        var overlap = db.SumBuckets(
            [("All", @"C:\"), ("Win", @"C:\W")], "Other");
        Assert.Equal(12, overlap["All"].Files);
        Assert.DoesNotContain("Win", overlap.Keys);
    }

    [Fact]
    public void QueryChildRollup_RollsSubtrees()
    {
        using var db = NewDb();
        Seed(db);
        var kids = db.QueryChildRollup(@"C:\U", CancellationToken.None);
        var sub = kids.Single(k => k.Name == "sub" && k.IsDir);
        Assert.Equal(2, sub.Files);
        Assert.Equal(2300, sub.Bytes);
        var files = kids.Where(k => !k.IsDir).ToList();
        Assert.Equal(3, files.Count);
        Assert.All(files, f => Assert.Equal(1, f.Files));
    }

    [Fact]
    public void QueryDuplicateSets_PagedByWasted_ExcludesNullHash()
    {
        using var db = NewDb();
        Seed(db);
        var (sets, totalSets, totalWasted) = db.QueryDuplicateSets(10, 0);
        Assert.Equal(4, totalSets);
        // (200-100 excluded: same-name pair counts once per hash)
        // h1:1*100 h2:1*400 h3:1*600 h5:1*1000 (MIN size per set)
        Assert.Equal(2100, totalWasted);
        Assert.Equal(4, sets.Count);
        Assert.Equal("h5", sets[0].Hash);
        Assert.Equal(2, sets[0].Copies);
        Assert.Equal(2, sets[0].Paths.Count);
        var (page2, _, _) = db.QueryDuplicateSets(2, 2);
        Assert.Equal(2, page2.Count);
        Assert.Equal("h2", page2[0].Hash);
    }

    [Fact]
    public void QueryAttrStats_ReportsFlags()
    {
        using var db = NewDb();
        Seed(db);
        var stats = db.QueryAttrStats();
        Assert.Equal(2, stats.SparseFiles);
        Assert.Equal(1400, stats.SparseBytes);
        Assert.Equal(2, stats.PlaceholderFiles);
        Assert.Equal(1500, stats.PlaceholderBytes);
        Assert.Equal(2, stats.HashMissingFiles);
    }

    [Fact]
    public void Upsert_InvalidatesTier_OnStatChange_Keeps_OnSameStat()
    {
        using var db = NewDb();
        Seed(db);
        db.UpsertFingerprint(@"C:\W\a.log", 100, 1000, "h1", 8);
        var kept = db.GetFingerprint(@"C:\W\a.log");
        Assert.NotNull(kept);
        Assert.Equal("SAFE", kept.Tier);
        db.UpsertFingerprint(@"C:\W\a.log", 150, 1000, "h1", 8);
        var cleared = db.GetFingerprint(@"C:\W\a.log");
        Assert.NotNull(cleared);
        Assert.Null(cleared.Tier);
        Assert.Equal(0, cleared.ClassGen);
    }

    [Fact]
    public void ClassifyChunk_Loop_FillsAllTiers()
    {
        using var db = NewDb();
        db.UpsertFingerprint(@"C:\A\a.bin", 10, 1, null, 1);
        db.UpsertFingerprint(@"C:\A\b.bin", 20, 2, null, 1);
        db.UpsertFingerprint(@"C:\B\c.bin", 30, 3, null, 1);
        Assert.Equal(3, db.CountUnclassified(0));
        string? after = null;
        long done = 0;
        while (true)
        {
            var chunk = db.QueryUnclassifiedChunk(after, 2, 0);
            if (chunk.Count == 0)
            {
                break;
            }

            db.UpdateClassifications(chunk
                .Select(f => (f.Path, "SAFE", (string?)"r", 1)).ToList());
            done += chunk.Count;
            after = chunk[chunk.Count - 1].Path;
            if (chunk.Count < 2)
            {
                break;
            }
        }

        Assert.Equal(3, done);
        Assert.Equal(0, db.CountUnclassified(0));
        var page = db.QueryInventoryPage(new InventoryQuery(Tier: "SAFE", Limit: 10));
        Assert.Equal(3, page.TotalMatches);
    }

    [Fact]
    public void OrphanDirs_Replace_Query_Paged()
    {
        using var db = NewDb();
        db.ReplaceOrphanDirs([
            (@"C:\X\old\", 100, "NoUninstallEntry"),
            (@"C:\X\older\", 200, "NoUninstallEntry"),
            (@"C:\Y\gone\", 300, "NoUninstallEntry"),
        ]);
        var p1 = db.QueryOrphanDirs(2, 0, out long total);
        Assert.Equal(3, total);
        Assert.Equal(2, p1.Count);
        var p2 = db.QueryOrphanDirs(2, 2, out _);
        Assert.Single(p2);
        db.ReplaceOrphanDirs([]);
        _ = db.QueryOrphanDirs(10, 0, out long empty);
        Assert.Equal(0, empty);
    }

    [Fact]
    public void Meta_Roundtrips()
    {
        using var db = NewDb();
        Assert.Null(db.GetMeta("k"));
        db.SetMeta("k", "v1");
        Assert.Equal("v1", db.GetMeta("k"));
        db.SetMeta("k", "v2");
        Assert.Equal("v2", db.GetMeta("k"));
    }

    [Fact]
    public void Migration_OldTable_GainsColumns()
    {
        string path = Path.Combine(_dir, "old.db");
        using (var conn = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={path}"))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE Fingerprints(
                    Path TEXT PRIMARY KEY, Size INTEGER NOT NULL,
                    MTimeUtcTicks INTEGER NOT NULL, Hash TEXT NULL,
                    LastSeenGeneration INTEGER NOT NULL);
                INSERT INTO Fingerprints VALUES('C:\o.bin', 5, 9, NULL, 3);
                """;
            cmd.ExecuteNonQuery();
        }

        using var db = new SentinelDb(path);
        var row = db.GetFingerprint(@"C:\o.bin");
        Assert.NotNull(row);
        Assert.Null(row.Tier);
        Assert.Equal(0, row.AttrFlags);
        Assert.Equal(0, row.ClassGen);
        Assert.Equal(1, db.CountUnclassified(0));
    }
}
