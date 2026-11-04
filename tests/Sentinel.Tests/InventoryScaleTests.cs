using System.Text.Json;
using Sentinel.Engine.Policy;
using Sentinel.Store;

namespace Sentinel.Tests;

// P22 scale proof. Consistency (10k rows) always runs: pages cover
// the stated total, buckets partition it, duplicates are exact.
// Perf (100k rows) runs only with SENTINEL_SCALE_PERF=1 and writes
// machine-measured latencies (no assertions on wall time —
// characterization, compared across reps in p22-run.md).
public sealed class InventoryScaleTests : IDisposable
{
    private readonly string _dir;

    public InventoryScaleTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "sentinel-p22s-" + Guid.NewGuid().ToString("N"));
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

    private static void SeedMixed(SentinelDb db, int count, int generation)
    {
        string[] dirs = [@"C:\W", @"C:\P", @"C:\U", @"D:\Data"];
        string[] exts = [".log", ".tmp", ".dat", ".bin"];
        db.BeginBulk();
        try
        {
            for (int i = 0; i < count; i++)
            {
                string dir = dirs[i % dirs.Length];
                string sub = (i % 7 == 0) ? @"\sub" : string.Empty;
                string path = $"{dir}{sub}\\file{i:D6}{exts[i % exts.Length]}";
                // Every 11th file shares a hash (duplicate sets).
                string? hash = i % 11 == 0 ? "DUP" + (i % 33) : "U" + i;
                int flags = 0;
                if (i % 13 == 0)
                {
                    flags |= FingerprintAttrs.Sparse;
                }

                if (i % 17 == 0)
                {
                    flags |= FingerprintAttrs.Placeholder;
                }

                db.UpsertFingerprint(path, 100 + (i % 5000), 1000 + i, hash, generation, flags);
            }
        }
        finally
        {
            db.EndBulk();
        }
    }

    [Fact]
    public void Scale_10k_Pages_Cover_Stated_Total()
    {
        using var db = new SentinelDb(Path.Combine(_dir, "s10k.db"));
        SeedMixed(db, 10000, 1);

        var seen = new HashSet<string>(StringComparer.Ordinal);
        long total = -1;
        for (int offset = 0; ; offset += 500)
        {
            var page = db.QueryInventoryPage(new InventoryQuery(Limit: 500, Offset: offset));
            if (total < 0)
            {
                total = page.TotalMatches;
            }

            Assert.Equal(total, page.TotalMatches);
            foreach (var row in page.Rows)
            {
                Assert.True(seen.Add(row.Path));
            }

            if (page.Rows.Count < 500)
            {
                break;
            }
        }

        Assert.Equal(10000, total);
        Assert.Equal(10000, seen.Count);
        Assert.Equal(db.CountFingerprints(), seen.Count);
    }

    [Fact]
    public void Scale_10k_Buckets_Partition_Total_No_Double_Count()
    {
        using var db = new SentinelDb(Path.Combine(_dir, "b10k.db"));
        SeedMixed(db, 10000, 1);

        var buckets = db.SumBuckets(
            [("W", @"C:\W"), ("P", @"C:\P"), ("U", @"C:\U")], "Rest");
        Assert.Equal(db.CountFingerprints(), buckets.Values.Sum(v => v.Files));
        Assert.Equal(db.SumFingerprintBytes(), buckets.Values.Sum(v => v.Bytes));
        // Each bucket is exact: spot-check one against a direct page.
        var w = db.QueryInventoryPage(new InventoryQuery(DirPrefixes: [@"C:\W"], Limit: 1));
        Assert.Equal(w.TotalMatches, buckets["W"].Files);
        Assert.Equal(w.TotalBytes, buckets["W"].Bytes);
    }

    [Fact]
    public void Scale_10k_Duplicate_Totals_Are_Exact()
    {
        using var db = new SentinelDb(Path.Combine(_dir, "d10k.db"));
        SeedMixed(db, 10000, 1);

        var (_, totalSets, totalWasted) = db.QueryDuplicateSets(1, 0);
        // i%11==0 over 10000 rows: 910 members in 3 hash groups
        // (DUP0/DUP11/DUP22 by i%33); wasted = (copies-1)*minSize.
        Assert.Equal(3, totalSets);
        var (sets, _, wasted2) = db.QueryDuplicateSets(10, 0);
        Assert.Equal(3, sets.Count);
        Assert.Equal(totalWasted, wasted2);
        long expect = sets.Sum(s => s.SizeBytes * (s.Copies - 1));
        Assert.Equal(expect, totalWasted);
    }

    [Fact]
    public void Scale_10k_Classify_Fills_All_Tiers()
    {
        using var db = new SentinelDb(Path.Combine(_dir, "c10k.db"));
        SeedMixed(db, 10000, 1);

        var progress = new List<ClassifyProgress>();
        new InventoryClassifier(db, []).EnsureClassified(
            DateTime.UtcNow, CancellationToken.None, p => progress.Add(p));
        Assert.Equal(0, db.CountUnclassified(0));
        Assert.NotEmpty(progress);
        Assert.Equal(progress[^1].Total, progress[^1].Done);
        var groups = db.CountGroupByTier().ToDictionary(g => g.Tier);
        Assert.False(groups.ContainsKey(string.Empty));
        Assert.Equal(10000, groups.Values.Sum(g => g.Files));
    }

    [Fact]
    public void Scale_100k_Perf_Characterization()
    {
        if (Environment.GetEnvironmentVariable("SENTINEL_SCALE_PERF") != "1")
        {
            return;
        }

        string outPath = Environment.GetEnvironmentVariable("SENTINEL_SCALE_OUT")
            ?? Path.Combine(Path.GetTempPath(), "p22-perf.json");
        using var db = new SentinelDb(Path.Combine(_dir, "p100k.db"));
        var ms = new Dictionary<string, double>();
        var sw = System.Diagnostics.Stopwatch.StartNew();

        SeedMixed(db, 100000, 1);
        ms["seed100k_ms"] = sw.Elapsed.TotalMilliseconds;

        sw.Restart();
        new InventoryClassifier(db, []).EnsureClassified(
            DateTime.UtcNow, CancellationToken.None);
        ms["classify100k_ms"] = sw.Elapsed.TotalMilliseconds;

        sw.Restart();
        var tiers = db.CountGroupByTier();
        ms["tierStrip_ms"] = sw.Elapsed.TotalMilliseconds;

        // Page the DOMINANT tier (a real full page, not an empty one).
        string topTier = tiers.OrderByDescending(g => g.Files).First().Tier;
        sw.Restart();
        var page = db.QueryInventoryPage(new InventoryQuery(Tier: topTier, Limit: 100));
        ms["tierPage_ms"] = sw.Elapsed.TotalMilliseconds;

        sw.Restart();
        var search = db.QueryInventoryPage(new InventoryQuery(NameContains: "file005", Limit: 100));
        ms["searchPage_ms"] = sw.Elapsed.TotalMilliseconds;

        sw.Restart();
        var buckets = db.SumBuckets(
            [("W", @"C:\W"), ("P", @"C:\P"), ("U", @"C:\U")], "Rest");
        ms["buckets_ms"] = sw.Elapsed.TotalMilliseconds;

        sw.Restart();
        var tops = new List<InventoryPage>();
        foreach (var dir in new[] { @"C:\W", @"C:\P", @"C:\U" })
        {
            tops.Add(db.QueryInventoryPage(new InventoryQuery(DirPrefixes: [dir], Limit: 5)));
        }

        ms["treemapTops_ms"] = sw.Elapsed.TotalMilliseconds;

        sw.Restart();
        var (sets, totalSets, totalWasted) = db.QueryDuplicateSets(100, 0);
        ms["dupeSets_ms"] = sw.Elapsed.TotalMilliseconds;

        sw.Restart();
        var rollup = db.QueryChildRollup(@"C:\W", CancellationToken.None);
        ms["rollup_ms"] = sw.Elapsed.TotalMilliseconds;

        sw.Restart();
        var attrs = db.QueryAttrStats();
        ms["attrStats_ms"] = sw.Elapsed.TotalMilliseconds;

        var report = new Dictionary<string, object>
        {
            ["rows"] = 100000,
            ["topTier"] = topTier,
            ["tierPageRows"] = page.Rows.Count,
            ["tierPageTotal"] = page.TotalMatches,
            ["searchTotal"] = search.TotalMatches,
            ["tierGroups"] = tiers.Count,
            ["buckets"] = buckets.Keys.ToArray(),
            ["dupeSets"] = totalSets,
            ["rollupChildren"] = rollup.Count,
            ["sparseFiles"] = attrs.SparseFiles,
            ["ms"] = ms,
        };
        File.WriteAllText(outPath, JsonSerializer.Serialize(
            report, new JsonSerializerOptions { WriteIndented = true }));
    }
}
