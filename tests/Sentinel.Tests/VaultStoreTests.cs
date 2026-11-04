using System.Security.Cryptography;
using System.Text;
using Sentinel.Engine.Actions;
using Sentinel.Store;

namespace Sentinel.Tests;

// E32: the vault manifest, layout, file seam, and startup recovery.
// Recovery completes bookkeeping only — it never moves, deletes, or
// "finishes" a file mutation, and every test below proves it.
public sealed class VaultStoreTests : IDisposable
{
    private readonly string _root;
    private readonly string _dbPath;
    private readonly string _vaultRoot;
    private readonly DiskVaultFileIO _io = new();
    private bool _disposed;

    public VaultStoreTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "sentinel-e32-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
        _dbPath = Path.Combine(_root, "vault.db");
        _vaultRoot = Path.Combine(_root, "vault");
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch
        {
            // Best effort: temp cleanup never fails the test.
        }
    }

    private static string ShaOf(string text) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    private VaultItem Item(
        string id, string original, string rel, long size, string sha,
        string status = VaultStatus.InterruptedMove, bool verified = false,
        string batch = "B1")
    {
        return new VaultItem(id, batch, original, rel, "C", size, sha,
            "2026-11-04T00:00:00Z", "clean_items_to_vault", "user",
            status, verified, null, null, null, string.Empty);
    }

    [Theory]
    [InlineData(@"C:\a\b.txt", "C")]
    [InlineData(@"D:\", "D")]
    [InlineData(@"\\srv\share\dir\f.txt", "srv_share")]
    [InlineData("relative.txt", "volume")]
    public void VolumeLabelFor_Matrix(string path, string expected)
    {
        Assert.Equal(expected, VaultLayout.VolumeLabelFor(path));
    }

    [Fact]
    public void ItemFileName_EmbedsRefAndSanitizes()
    {
        Assert.Equal("V-1__photo.jpg", VaultLayout.ItemFileName("V-1", "photo.jpg"));
        string bad = "a<b>c";
        string named = VaultLayout.ItemFileName("V-2", bad);
        Assert.StartsWith("V-2__", named);
        Assert.DoesNotContain("<", named);
        Assert.DoesNotContain(">", named);
        string longName = new string('x', 200) + ".txt";
        Assert.True(VaultLayout.ItemFileName("V-3", longName).Length <= "V-3__".Length + 120);
        Assert.Equal("V-4__item", VaultLayout.ItemFileName("V-4", "   ...   "));
    }

    [Fact]
    public void RestoreConflictPath_FirstFreeWins()
    {
        var taken = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            @"C:\docs\photo.jpg",
            @"C:\docs\photo (restored 1).jpg",
        };
        Assert.Equal(
            @"C:\docs\photo (restored 2).jpg",
            VaultLayout.RestoreConflictPath(@"C:\docs\photo.jpg", taken.Contains));
        Assert.Equal(
            @"C:\docs\other.jpg",
            VaultLayout.RestoreConflictPath(@"C:\docs\other.jpg", taken.Contains));
        Assert.Equal(
            @"C:\docs\LICENSE (restored 1).txt",
            VaultLayout.RestoreConflictPath(@"C:\docs\LICENSE (restored 1).txt", taken.Contains));
    }

    [Fact]
    public void StoreLayout_VaultAndAuditDerives()
    {
        string anchor = Path.Combine("C:", "d", "sentinel.db");
        Assert.Equal(
            Path.Combine("C:", "d", "sentinel-vault.db"),
            StoreLayout.DeriveVaultDbPath(anchor));
        Assert.Equal(
            Path.Combine("C:", "d", "sentinel-audit.db"),
            StoreLayout.DeriveAuditDbPath(anchor));
        Assert.Equal(
            Path.Combine("C:", "d", "sentinel-vault"),
            StoreLayout.DeriveVaultDir(anchor));
    }

    [Fact]
    public void Batch_Lifecycle()
    {
        using var store = new VaultStore(_dbPath);
        Assert.True(store.TryBeginBatch("K1", "B1", "clean_items_to_vault",
            "2026-11-04T00:00:00Z", out string? existing));
        Assert.Null(existing);

        var batch = store.GetBatch("K1");
        Assert.NotNull(batch);
        Assert.Equal("B1", batch.BatchId);
        Assert.Equal("Running", batch.Status);
        Assert.Null(batch.FinishedUtc);

        store.FinishBatch("K1", "Completed", "all done", "2026-11-04T00:01:00Z");
        var done = store.GetBatch("K1");
        Assert.NotNull(done);
        Assert.Equal("Completed", done.Status);
        Assert.Equal("all done", done.Note);
        Assert.Equal("2026-11-04T00:01:00Z", done.FinishedUtc);
    }

    [Fact]
    public void Batch_DuplicateKey_ReturnsOriginalBatch()
    {
        using var store = new VaultStore(_dbPath);
        Assert.True(store.TryBeginBatch("K9", "B-first", "clean_items_to_vault",
            "2026-11-04T00:00:00Z", out _));
        Assert.False(store.TryBeginBatch("K9", "B-second", "clean_items_to_vault",
            "2026-11-04T00:00:01Z", out string? existing));
        Assert.Equal("B-first", existing);
    }

    [Fact]
    public void RecordItem_Get_RoundTrips()
    {
        using var store = new VaultStore(_dbPath);
        var item = Item("V-1", @"C:\t\a.tmp", "V-1__a.tmp", 12, ShaOf("x")) with
        {
            Status = VaultStatus.Quarantined,
            Verified = true,
            ReviewDueUtc = "2026-12-04T00:00:00Z",
            Detail = "moved",
        };
        store.RecordItem(item);

        var read = store.Get("V-1");
        Assert.NotNull(read);
        Assert.Equal(item, read);
    }

    [Fact]
    public void ListRestorable_OnlyVerifiedQuarantined()
    {
        using var store = new VaultStore(_dbPath);
        store.RecordItem(Item("V-ok", @"C:\t\a", "r-a", 1, "S") with
        {
            Status = VaultStatus.Quarantined,
            Verified = true,
        });
        store.RecordItem(Item("V-unverified", @"C:\t\b", "r-b", 1, "S") with
        {
            Status = VaultStatus.Quarantined,
            Verified = false,
        });
        store.RecordItem(Item("V-interrupted", @"C:\t\c", "r-c", 1, "S"));
        store.RecordItem(Item("V-restored", @"C:\t\d", "r-d", 1, "S") with
        {
            Status = VaultStatus.Restored,
            Verified = true,
        });

        var restorable = store.ListRestorable();
        var single = Assert.Single(restorable);
        Assert.Equal("V-ok", single.Id);
        Assert.Equal(4, store.ListAll().Count);
    }

    [Fact]
    public void MarkRestored_MarkSuperseded_SetReviewDue()
    {
        using var store = new VaultStore(_dbPath);
        store.RecordItem(Item("V-r", @"C:\t\a", "r-a", 1, "S") with
        {
            Status = VaultStatus.Quarantined,
            Verified = true,
        });
        store.RecordItem(Item("V-s", @"C:\t\b", "r-b", 1, "S"));

        store.MarkRestored("V-r", "2026-11-05T00:00:00Z", @"C:\t\a", "user undo");
        store.MarkSuperseded("V-s", "superseded by B2");
        store.SetReviewDue("V-r", "2026-12-05T00:00:00Z");

        var restored = store.Get("V-r");
        Assert.NotNull(restored);
        Assert.Equal(VaultStatus.Restored, restored.Status);
        Assert.Equal(@"C:\t\a", restored.RestoredPath);
        Assert.Equal("2026-12-05T00:00:00Z", restored.ReviewDueUtc);
        Assert.Equal(VaultStatus.Superseded, store.Get("V-s")?.Status);
    }

    [Fact]
    public void QueryRetainedBytes_CountsVerifiedQuarantinedOnly()
    {
        using var store = new VaultStore(_dbPath);
        store.RecordItem(Item("V-1", @"C:\t\a", "r-a", 100, "S") with
        {
            Status = VaultStatus.Quarantined,
            Verified = true,
        });
        store.RecordItem(Item("V-2", @"C:\t\b", "r-b", 200, "S") with
        {
            Status = VaultStatus.Quarantined,
            Verified = true,
        });
        store.RecordItem(Item("V-3", @"C:\t\c", "r-c", 1000, "S") with
        {
            Status = VaultStatus.Quarantined,
            Verified = false,
        });
        store.RecordItem(Item("V-4", @"C:\t\d", "r-d", 500, "S") with
        {
            Status = VaultStatus.Restored,
            Verified = true,
        });
        store.RecordItem(Item("V-5", @"C:\t\e", "r-e", 700, "S"));

        Assert.Equal(300, store.QueryRetainedBytes());
    }

    [Fact]
    public void FindInterrupted_ReturnsOnlyResidue()
    {
        using var store = new VaultStore(_dbPath);
        store.RecordItem(Item("V-m", @"C:\t\a", "r-a", 1, "S",
            VaultStatus.InterruptedMove));
        store.RecordItem(Item("V-r", @"C:\t\b", "r-b", 1, "S",
            VaultStatus.InterruptedRestore));
        store.RecordItem(Item("V-q", @"C:\t\c", "r-c", 1, "S") with
        {
            Status = VaultStatus.Quarantined,
            Verified = true,
        });

        var rows = store.FindInterrupted().Select(i => i.Id).OrderBy(id => id).ToList();
        Assert.Equal(["V-m", "V-r"], rows);
    }

    private string WriteSource(string name, string content)
    {
        string dir = Path.Combine(_root, "src");
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, name);
        File.WriteAllText(path, content);
        return path;
    }

    private string WriteVaultCopy(string rel, string content)
    {
        string dir = Path.Combine(_vaultRoot, "C");
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, rel);
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public void Reconcile_MoveFinishedOnDisk_CompletesBookkeeping()
    {
        using var store = new VaultStore(_dbPath);
        string content = "moved-bytes-1";
        string rel = "V-10__a.tmp";
        WriteVaultCopy(rel, content);
        string gone = Path.Combine(_root, "src", "a.tmp");
        store.RecordItem(Item("V-10", gone, rel, content.Length, ShaOf(content)));

        var report = store.ReconcileInterrupted(
            _vaultRoot, _io.ComputeSha256, "2026-11-04T01:00:00Z");

        Assert.Equal(1, report.BookkeepingCompleted);
        var finding = Assert.Single(report.Findings);
        Assert.Equal("BookkeepingCompleted", finding.Outcome);
        var row = store.Get("V-10");
        Assert.NotNull(row);
        Assert.Equal(VaultStatus.Quarantined, row.Status);
        Assert.True(row.Verified);
    }

    [Fact]
    public void Reconcile_SourcePresent_VaultValid_NeedsDecision_RowUnchanged()
    {
        using var store = new VaultStore(_dbPath);
        string content = "kept-bytes-2";
        string rel = "V-11__b.tmp";
        string source = WriteSource("b.tmp", content);
        WriteVaultCopy(rel, content);
        store.RecordItem(Item("V-11", source, rel, content.Length, ShaOf(content)));

        var report = store.ReconcileInterrupted(
            _vaultRoot, _io.ComputeSha256, "2026-11-04T01:00:00Z");

        Assert.Equal(1, report.NeedsUserDecision);
        Assert.Equal(0, report.BookkeepingCompleted);
        Assert.Equal(VaultStatus.InterruptedMove, store.Get("V-11")?.Status);
        // Both copies untouched.
        Assert.Equal(content, File.ReadAllText(source));
    }

    [Fact]
    public void Reconcile_SourcePresent_VaultMissing_NeedsDecision()
    {
        using var store = new VaultStore(_dbPath);
        string content = "kept-bytes-3";
        string source = WriteSource("c.tmp", content);
        store.RecordItem(Item("V-12", source, "V-12__c.tmp", content.Length, ShaOf(content)));

        var report = store.ReconcileInterrupted(
            _vaultRoot, _io.ComputeSha256, "2026-11-04T01:00:00Z");

        Assert.Equal(1, report.NeedsUserDecision);
        Assert.Contains("incomplete", report.Findings[0].Detail);
        Assert.Equal(content, File.ReadAllText(source));
    }

    [Fact]
    public void Reconcile_BothGone_BytesMissing_RowUnchanged()
    {
        using var store = new VaultStore(_dbPath);
        store.RecordItem(Item("V-13", Path.Combine(_root, "src", "d.tmp"),
            "V-13__d.tmp", 5, ShaOf("lost"), VaultStatus.InterruptedMove));

        var report = store.ReconcileInterrupted(
            _vaultRoot, _io.ComputeSha256, "2026-11-04T01:00:00Z");

        Assert.Equal(1, report.BytesMissing);
        Assert.Contains("cannot be recovered", report.Findings[0].Detail);
        Assert.Equal(VaultStatus.InterruptedMove, store.Get("V-13")?.Status);
    }

    [Fact]
    public void Reconcile_VaultCorrupt_SourceGone_BytesMissing()
    {
        using var store = new VaultStore(_dbPath);
        string rel = "V-14__e.tmp";
        WriteVaultCopy(rel, "corrupted!!!");
        store.RecordItem(Item("V-14", Path.Combine(_root, "src", "e.tmp"),
            rel, 11, ShaOf("original!!!")));

        var report = store.ReconcileInterrupted(
            _vaultRoot, _io.ComputeSha256, "2026-11-04T01:00:00Z");

        Assert.Equal(1, report.BytesMissing);
    }

    [Fact]
    public void Reconcile_RestoreFinishedOnDisk_CompletesToRestored()
    {
        using var store = new VaultStore(_dbPath);
        string content = "restored-bytes-6";
        string source = WriteSource("f.tmp", content);
        store.RecordItem(Item("V-15", source, "V-15__f.tmp", content.Length, ShaOf(content),
            VaultStatus.InterruptedRestore));

        var report = store.ReconcileInterrupted(
            _vaultRoot, _io.ComputeSha256, "2026-11-04T01:00:00Z");

        Assert.Equal(1, report.BookkeepingCompleted);
        var row = store.Get("V-15");
        Assert.NotNull(row);
        Assert.Equal(VaultStatus.Restored, row.Status);
        Assert.Equal("2026-11-04T01:00:00Z", row.RestoredUtc);
        Assert.Equal(source, row.RestoredPath);
    }

    [Fact]
    public void Reconcile_RestoreAmbiguous_BothPresent_NeedsDecision()
    {
        using var store = new VaultStore(_dbPath);
        string content = "ambiguous-7";
        string rel = "V-16__g.tmp";
        string source = WriteSource("g.tmp", content);
        WriteVaultCopy(rel, content);
        store.RecordItem(Item("V-16", source, rel, content.Length, ShaOf(content),
            VaultStatus.InterruptedRestore));

        var report = store.ReconcileInterrupted(
            _vaultRoot, _io.ComputeSha256, "2026-11-04T01:00:00Z");

        Assert.Equal(1, report.NeedsUserDecision);
        Assert.Equal(VaultStatus.InterruptedRestore, store.Get("V-16")?.Status);
    }

    [Fact]
    public void Reconcile_RestoreNeverStarted_VaultValid_FlipsToQuarantined()
    {
        using var store = new VaultStore(_dbPath);
        string content = "still-safe-8";
        string rel = "V-17__h.tmp";
        WriteVaultCopy(rel, content);
        store.RecordItem(Item("V-17", Path.Combine(_root, "src", "h.tmp"),
            rel, content.Length, ShaOf(content), VaultStatus.InterruptedRestore));

        var report = store.ReconcileInterrupted(
            _vaultRoot, _io.ComputeSha256, "2026-11-04T01:00:00Z");

        Assert.Equal(1, report.BookkeepingCompleted);
        Assert.Contains("had not started", report.Findings[0].Detail);
        Assert.Equal(VaultStatus.Quarantined, store.Get("V-17")?.Status);
    }

    [Fact]
    public void Reconcile_PerformsNoFileMutation()
    {
        using var store = new VaultStore(_dbPath);
        string keep = WriteSource("keep.tmp", "keep-me");
        string rel = "V-18__keep.tmp";
        WriteVaultCopy(rel, "keep-me");
        store.RecordItem(Item("V-18", keep, rel, 7, ShaOf("keep-me")));
        store.RecordItem(Item("V-19", Path.Combine(_root, "src", "lost.tmp"),
            "V-19__lost.tmp", 4, ShaOf("lost")));

        var before = SnapshotFiles();
        store.ReconcileInterrupted(_vaultRoot, _io.ComputeSha256, "2026-11-04T01:00:00Z");
        var after = SnapshotFiles();

        Assert.Equal(before, after);
    }

    [Fact]
    public void Reconcile_HashReaderThrows_TreatedAsInvalid()
    {
        using var store = new VaultStore(_dbPath);
        string rel = "V-20__i.tmp";
        WriteVaultCopy(rel, "bytes");
        store.RecordItem(Item("V-20", Path.Combine(_root, "src", "i.tmp"),
            rel, 5, ShaOf("bytes")));

        string? Boom(string path) => throw new IOException("disk hiccup");
        var report = store.ReconcileInterrupted(_vaultRoot, Boom, "2026-11-04T01:00:00Z");

        Assert.Equal(1, report.BytesMissing);
    }

    private Dictionary<string, string> SnapshotFiles()
    {
        var snap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string dir in new[] { Path.Combine(_root, "src"), _vaultRoot })
        {
            if (!Directory.Exists(dir))
            {
                continue;
            }

            foreach (string file in Directory.GetFiles(dir, "*", SearchOption.AllDirectories))
            {
                snap[file] = _io.ComputeSha256(file);
            }
        }

        return snap;
    }

    [Fact]
    public void DiskIO_Move_RoundTrip_ByteIdentical()
    {
        string src = WriteSource("move.tmp", "move-me-bytes");
        string dstDir = Path.Combine(_root, "dst");
        _io.CreateDirectory(dstDir);
        string dst = Path.Combine(dstDir, "move.tmp");

        string before = _io.ComputeSha256(src);
        long size = _io.GetSize(src);
        _io.MoveFile(src, dst);

        Assert.False(_io.FileExists(src));
        Assert.True(_io.FileExists(dst));
        Assert.Equal(size, _io.GetSize(dst));
        Assert.Equal(before, _io.ComputeSha256(dst));
    }

    [Fact]
    public void DiskIO_Move_RefusesOverwrite()
    {
        string src = WriteSource("src.tmp", "new");
        string dst = WriteSource("dst.tmp", "existing");
        Assert.Throws<IOException>(() => _io.MoveFile(src, dst));
        Assert.Equal("existing", File.ReadAllText(dst));
        Assert.Equal("new", File.ReadAllText(src));
    }

    [Fact]
    public void DiskIO_Sha256_KnownVector()
    {
        string path = WriteSource("abc.txt", "abc");
        Assert.Equal(
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
            _io.ComputeSha256(path));
    }
}
