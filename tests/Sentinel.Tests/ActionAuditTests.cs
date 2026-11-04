using System.Text.Json;
using Sentinel.App.Services;
using Sentinel.Engine.Actions;
using Sentinel.Store;

namespace Sentinel.Tests;

// E34: append-only hash-chained audit log. Every tamper shape
// (modify, delete, reorder-by-swap, insert, link-break) is detected
// with the breaking sequence number; seal rotation preserves the
// link; exports escape hostile content.
public sealed class ActionAuditTests : IDisposable
{
    private readonly string _root;
    private bool _disposed;

    public ActionAuditTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "sentinel-e34-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch
        {
            // Best effort: temp cleanup never fails the test.
        }
    }

    private string DbPath(string name = "audit.db") => Path.Combine(_root, name);

    private static ActionAuditLog Open(string path) =>
        new(path, appVersion: "9.9-test", modelId: "model-t", packVersion: "pack-t");

    private static long Append(ActionAuditLog log, string detail, string action = "clean_items_to_vault") =>
        log.Append("2026-11-04T00:00:00Z", "user", action, "[\"f:1\"]",
            null, string.Empty, "{\"done\":true}", "Vault:V-1", "Available", detail);

    private void Tamper(string path, string sql)
    {
        using var raw = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={path}");
        raw.Open();
        using var cmd = raw.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    [Fact]
    public void Append_VerifyChain_Ok_FieldsRoundTrip()
    {
        using var log = Open(DbPath());
        Assert.Equal(1, Append(log, "first"));
        Assert.Equal(2, Append(log, "second", "export_report"));
        Assert.Equal(3, Append(log, "third"));

        var integrity = log.VerifyChain();
        Assert.True(integrity.Ok);
        Assert.Contains("tip seq 3", integrity.Detail);

        var recent = log.ListRecent(10);
        Assert.Equal([3L, 2L, 1L], recent.Select(e => e.Seq).ToList());
        var first = recent[2];
        Assert.Equal("user", first.Actor);
        Assert.Equal("clean_items_to_vault", first.ActionId);
        Assert.Equal("[\"f:1\"]", first.FindingIdsJson);
        Assert.Equal("9.9-test", first.AppVersion);
        Assert.Equal("model-t", first.ModelId);
        Assert.Equal("pack-t", first.PackVersion);
        Assert.Equal("Vault:V-1", first.BackupRef);
        Assert.Equal("Available", first.UndoState);
        var (detail, after) = ActionAuditLog.SplitAfter(first.AfterJson);
        Assert.Equal("first", detail);
        Assert.Equal("{\"done\":true}", after);
        Assert.Equal(ActionAuditLog.GenesisHash, recent[2].PrevHash);
        Assert.Equal(3, log.Count());
    }

    [Fact]
    public void Tamper_ModifyAfterJson_DetectedAtSeq()
    {
        string path = DbPath();
        using var log = Open(path);
        Append(log, "one");
        Append(log, "two");
        Append(log, "three");

        Tamper(path, "UPDATE AuditEntries SET AfterJson = 'forged' WHERE Seq = 2;");

        var integrity = log.VerifyChain();
        Assert.False(integrity.Ok);
        Assert.Equal(2, integrity.BrokenAtSeq);
        Assert.Contains("Hash mismatch", integrity.Detail);
    }

    [Fact]
    public void Tamper_DeleteMiddleRow_DetectedAsGap()
    {
        string path = DbPath();
        using var log = Open(path);
        Append(log, "one");
        Append(log, "two");
        Append(log, "three");

        Tamper(path, "DELETE FROM AuditEntries WHERE Seq = 2;");

        var integrity = log.VerifyChain();
        Assert.False(integrity.Ok);
        Assert.Equal(3, integrity.BrokenAtSeq);
        Assert.Contains("Gap", integrity.Detail);
    }

    [Fact]
    public void Tamper_SwapContents_DetectedAtFirst()
    {
        string path = DbPath();
        using var log = Open(path);
        Append(log, "one");
        Append(log, "two");

        Tamper(path, """
            UPDATE AuditEntries SET AfterJson = CASE Seq WHEN 1 THEN 'second' || char(10) || '{}' ELSE 'first' || char(10) || '{}' END
            WHERE Seq IN (1, 2);
            """);

        var integrity = log.VerifyChain();
        Assert.False(integrity.Ok);
        Assert.Equal(1, integrity.BrokenAtSeq);
    }

    [Fact]
    public void Tamper_InsertExplicitSeq_DetectedAsGap()
    {
        string path = DbPath();
        using var log = Open(path);
        Append(log, "one");

        Tamper(path, """
            INSERT INTO AuditEntries(Seq, Utc, Actor, ActionId, FindingIdsJson, BeforeJson, AfterJson,
              BackupRef, UndoState, AppVersion, ModelId, PackVersion, PrevHash, EntryHash)
            VALUES (99, 't', 'user', 'x', '[]', '', '', 'none', 'NotApplicable',
              'v', 'm', 'p', 'forged-prev', 'forged-hash');
            """);

        var integrity = log.VerifyChain();
        Assert.False(integrity.Ok);
        Assert.Equal(99, integrity.BrokenAtSeq);
    }

    [Fact]
    public void Tamper_PrevHash_DetectedAsLinkBreak()
    {
        string path = DbPath();
        using var log = Open(path);
        Append(log, "one");
        Append(log, "two");

        Tamper(path, "UPDATE AuditEntries SET PrevHash = 'forged-prev' WHERE Seq = 2;");

        var integrity = log.VerifyChain();
        Assert.False(integrity.Ok);
        Assert.Equal(2, integrity.BrokenAtSeq);
        Assert.Contains("Link break", integrity.Detail);
    }

    [Fact]
    public void Seal_Rotation_LinksArchiveAndContinuesChain()
    {
        string path = DbPath();
        using var log = Open(path);
        Append(log, "one");
        Append(log, "two");

        string archive = Path.Combine(_root, "seal-1.json");
        var seal = log.Seal(archive, "2026-11-04T02:00:00Z");

        Assert.True(seal.Archived);
        Assert.Equal(2, seal.EntriesSealed);
        Assert.NotNull(seal.ArchiveHash);
        Assert.True(File.Exists(archive));
        Assert.Contains("unsigned", seal.Detail);

        using (var doc = JsonDocument.Parse(File.ReadAllText(archive)))
        {
            var root = doc.RootElement;
            Assert.Equal("sentinel-audit-seal/1", root.GetProperty("format").GetString());
            Assert.Equal(2, root.GetProperty("entryCount").GetInt32());
            Assert.Equal("unsigned-seal-signing-deferred",
                root.GetProperty("signatureStatus").GetString());
            Assert.True(root.GetProperty("signature").ValueKind == JsonValueKind.Null);
            Assert.Equal(2, root.GetProperty("entries").GetArrayLength());
        }

        Assert.Equal(0, log.Count());

        long next = Append(log, "three");
        Assert.Equal(3, next);
        var row = log.ListRecent(1)[0];
        Assert.Equal(seal.ArchiveHash, row.PrevHash);

        var integrity = log.VerifyChain();
        Assert.True(integrity.Ok);
        Assert.Contains("tip seq 3", integrity.Detail);
    }

    [Fact]
    public void Seal_RefusesBrokenChain_RowsIntact()
    {
        string path = DbPath();
        using var log = Open(path);
        Append(log, "one");
        Append(log, "two");
        Tamper(path, "UPDATE AuditEntries SET AfterJson = 'forged' WHERE Seq = 1;");

        var seal = log.Seal(Path.Combine(_root, "seal-bad.json"), "2026-11-04T02:00:00Z");

        Assert.False(seal.Archived);
        Assert.Contains("BROKEN", seal.Detail);
        Assert.Equal(2, log.Count());
    }

    [Fact]
    public void Seal_EmptyLog_Refuses()
    {
        using var log = Open(DbPath());
        var seal = log.Seal(Path.Combine(_root, "seal-empty.json"), "2026-11-04T02:00:00Z");
        Assert.False(seal.Archived);
        Assert.False(File.Exists(Path.Combine(_root, "seal-empty.json")));
    }

    [Fact]
    public void SizeAndThreshold_FreshDb_NoSealNeeded()
    {
        using var log = Open(DbPath());
        Assert.Equal(50L * 1024 * 1024, ActionAuditLog.SealThresholdBytes);
        Assert.False(log.NeedsSeal());
        Append(log, "one");
        Assert.True(log.SizeBytes() > 0);
        Assert.False(log.NeedsSeal());
    }

    [Fact]
    public void ExportJson_ParsesAndPreservesHostileDetail()
    {
        using var log = Open(DbPath());
        string hostile = "\"><script>alert(1)</script>&\"☃";
        Append(log, hostile);

        string json = AuditExport.BuildJson(
            log.ListRecent(10), log.VerifyChain(), "2026-11-04T03:00:00Z", "9.9-test");

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.Equal("sentinel-audit/1", root.GetProperty("format").GetString());
        Assert.True(root.GetProperty("integrity").GetProperty("ok").GetBoolean());
        var entries = root.GetProperty("entries");
        Assert.Equal(1, entries.GetArrayLength());
        Assert.Equal(hostile, entries[0].GetProperty("detail").GetString());
    }

    [Fact]
    public void ExportHtml_EscapesHostileContent()
    {
        using var log = Open(DbPath());
        Append(log, "\"><script>alert(1)</script>");

        string html = AuditExport.BuildHtml(
            log.ListRecent(10), log.VerifyChain(), "2026-11-04T03:00:00Z");

        Assert.DoesNotContain("<script>", html);
        Assert.Contains("&lt;script&gt;", html);
        Assert.Contains("Integrity OK", html);

        string broken = AuditExport.BuildHtml(
            log.ListRecent(10),
            new AuditIntegrity(false, 1, "Gap: expected seq 1 but found 2."),
            "2026-11-04T03:00:00Z");
        Assert.Contains("Integrity BROKEN", broken);
        Assert.DoesNotContain("Integrity OK", broken);
    }

    [Fact]
    public void ListByAction_Filters()
    {
        using var log = Open(DbPath());
        Append(log, "a", "clean_items_to_vault");
        Append(log, "b", "export_report");
        Append(log, "c", "clean_items_to_vault");

        var rows = log.ListByAction("export_report");
        var single = Assert.Single(rows);
        Assert.Equal(2, single.Seq);
        Assert.Equal(2, log.ListByAction("clean_items_to_vault").Count);
        Assert.Empty(log.ListByAction("driver_rollback"));
    }

    [Fact]
    public void SplitAfter_RoundTrip_AndLegacy()
    {
        var (detail, after) = ActionAuditLog.SplitAfter("hello\n{\"a\":1}");
        Assert.Equal("hello", detail);
        Assert.Equal("{\"a\":1}", after);
        var (legacy, empty) = ActionAuditLog.SplitAfter("no-newline");
        Assert.Equal("no-newline", legacy);
        Assert.Equal(string.Empty, empty);
    }

    [Fact]
    public void SinkAdapter_AppendsAndFailsClosed()
    {
        using var log = Open(DbPath());
        var sink = new AuditLogSink(() => log);
        var draft = new AuditDraft("scheduled", "clean_items_to_vault", ["f:1"],
            null, string.Empty, string.Empty, "none", "NotApplicable", "[Refused] nope");

        Assert.True(sink.TryAppend(draft, out long seq, out string error));
        Assert.Equal(1, seq);
        Assert.Empty(error);
        Assert.Equal("scheduled", log.ListRecent(1)[0].Actor);

        var missing = new AuditLogSink(() => null);
        Assert.False(missing.TryAppend(draft, out long badSeq, out string badError));
        Assert.Equal(-1, badSeq);
        Assert.NotEmpty(badError);
    }

    [Fact]
    public void SinkAdapter_DisposedLog_MapsToFalse()
    {
        var log = Open(DbPath("disposed.db"));
        var sink = new AuditLogSink(() => log);
        log.Dispose();

        var draft = new AuditDraft("user", "x", [], null, string.Empty,
            string.Empty, "none", "NotApplicable", "d");
        Assert.False(sink.TryAppend(draft, out long seq, out string error));
        Assert.Equal(-1, seq);
        Assert.Contains("ObjectDisposed", error);
    }
}
