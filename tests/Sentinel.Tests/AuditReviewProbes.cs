using System.Text;
using Sentinel.Engine.Agent;
using Sentinel.Engine.Inventory;
using Sentinel.Store;
using Xunit;

namespace Sentinel.Tests;

// Adopted 2026-10-31 from audit/2026-10-30-review/AuditReviewProbes.cs
// (SENTINEL_PROGRESS_REVIEW_2026-10-30 §3). Reviewer wrote these as
// failing-first probes against the 74b111f snapshot; they are now
// permanent regression tests. Probe 3 (Responses function_call)
// tracks P1-02 and stays red until the provider protocol lands.
public sealed class AuditReviewProbes
{
    private static string Fixture()
    {
        string root = Path.Combine(Path.GetTempPath(), "sentinel-review-fixture-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    [Fact]
    public async Task CompletedRescan_DoesNotCountADeletedFileAsCurrentInventory()
    {
        string root = Fixture();
        string scope = Path.Combine(root, "scope");
        Directory.CreateDirectory(scope);
        string file = Path.Combine(scope, "owned-fixture.txt");
        File.WriteAllText(file, "synthetic");
        using var db = new SentinelDb(Path.Combine(root, "inventory.db"));
        var scanner = new DiskInventoryScanner(db);
        var first = await scanner.ScanAsync(scope, 1);
        Assert.Equal(1, first.FilesSeen);
        File.Delete(file); // Exact file created above, never user data.
        var second = await scanner.ScanAsync(scope, 2);
        Assert.Equal(0, second.FilesSeen);
        Assert.Equal(0L, db.CountFingerprints());
    }

    [Fact]
    public void ApprovedUtf16Log_IsReadableAsText()
    {
        string root = Fixture();
        string file = Path.Combine(root, "diagnostic.log");
        File.WriteAllText(file, "Disk diagnostic fixture\n", Encoding.Unicode);
        var hub = new EvidencePreviewHub();
        using var store = new AgentStore(Path.Combine(root, "agent.db"));
        var broker = new ToolBroker(store);
        broker.Register(new ExcerptTools(hub));
        string id = broker.MintFileId(file);
        var scope = new InvestigationScope("review-utf16", new[] { root });
        var result = broker.Dispatch(scope,
            new ToolCallRequest("read_text_excerpt", new Dictionary<string, string> { ["file_id"] = id }),
            new InvestigationBudgets(), CancellationToken.None);
        Assert.Equal(ToolResultStatus.Ok, result.Status);
    }

    [Fact]
    public void DocumentedResponsesFunctionCall_IsParsed()
    {
        const string response = """
        {"id":"resp_fixture","object":"response","status":"completed","output":[{"type":"function_call","name":"get_scan_overview","arguments":"{}","call_id":"call_fixture","status":"completed"}]}
        """;
        var turn = MetaApiAdapter.ParseTurn(response);
        Assert.NotNull(turn.ToolRequest);
    }

    [Fact]
    public void UserProfileInsideDiagnosticText_IsRedacted()
    {
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        Assert.False(string.IsNullOrWhiteSpace(profile));
        string text = "Opened " + profile + "\\Documents\\diagnostic.log";
        Assert.DoesNotContain(profile, SecretRedactor.RedactUserPrefix(text), StringComparison.OrdinalIgnoreCase);
    }

    // ---- Closure hardening (2026-10-31): multi-root, gap, encoding,
    // and boundary cases the review asked to add to the suite. ----

    [Fact]
    public void Purge_SparesUnrelatedRoot_AndGapSubtree()
    {
        string root = Fixture();
        string scopeA = Path.Combine(root, "a");
        string scopeB = Path.Combine(root, "b");
        string gapDir = Path.Combine(scopeA, "locked");
        using var db = new SentinelDb(Path.Combine(root, "inventory.db"));
        db.UpsertFingerprint(Path.Combine(scopeA, "gone.txt"), 3, 1, null, 1);
        db.UpsertFingerprint(Path.Combine(scopeB, "other.txt"), 3, 1, null, 1);
        db.UpsertFingerprint(Path.Combine(gapDir, "unknown.txt"), 3, 1, null, 1);
        Assert.Equal(3L, db.CountFingerprints());

        int purged = db.DeleteFingerprintsNotSeenIn(scopeA, 2, [gapDir]);

        Assert.Equal(1, purged);
        Assert.Equal(2L, db.CountFingerprints());
        var paths = db.ListLargestFingerprints(10).Select(f => f.Path).ToList();
        Assert.DoesNotContain(Path.Combine(scopeA, "gone.txt"), paths);
        Assert.Contains(Path.Combine(scopeB, "other.txt"), paths);
        Assert.Contains(Path.Combine(gapDir, "unknown.txt"), paths);
    }

    [Fact]
    public void Purge_RootGap_DisablesPurgeForThatRoot()
    {
        string root = Fixture();
        string scope = Path.Combine(root, "scope");
        using var db = new SentinelDb(Path.Combine(root, "inventory.db"));
        db.UpsertFingerprint(Path.Combine(scope, "kept.txt"), 3, 1, null, 1);

        int purged = db.DeleteFingerprintsNotSeenIn(scope, 2, [scope]);

        Assert.Equal(0, purged);
        Assert.Equal(1L, db.CountFingerprints());
    }

    [Fact]
    public void Redaction_ReplacesAllOccurrences_AndForwardSlashes()
    {
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        Assert.False(string.IsNullOrWhiteSpace(profile));
        string fwd = profile.Replace(Path.DirectorySeparatorChar, '/');
        string text = $"first {profile}\\a.log then {fwd}/b.log end {profile}";
        string redacted = SecretRedactor.RedactUserPrefix(text);

        Assert.DoesNotContain(profile, redacted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(fwd, redacted, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(3, redacted.Split("<user>").Length - 1);
    }

    [Fact]
    public void SerializedContext_ContainsNoProfilePath()
    {
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        Assert.False(string.IsNullOrWhiteSpace(profile));
        var context = new ModelContext(
            $"Investigate {profile}\\scan",
            $"{profile}\\scopeA;{profile}\\scopeB",
            1, false, "{}", [], [], [], 0, 40, 0, 1000);

        string json = ModelContextSerializer.Serialize(context);

        Assert.DoesNotContain(profile, json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("<user>", json);
    }

    [Fact]
    public void Utf16BeLog_IsReadableAsText()
    {
        string root = Fixture();
        string file = Path.Combine(root, "be-diagnostic.log");
        File.WriteAllText(file, "Big-endian fixture\n", Encoding.BigEndianUnicode);
        Assert.Equal(ToolResultStatus.Ok, ExcerptStatus(root, file));
    }

    [Fact]
    public void Utf16PreambleWithDecodedNul_StaysDenied()
    {
        string root = Fixture();
        string file = Path.Combine(root, "nul-binary.log");
        File.WriteAllBytes(file, [0xFF, 0xFE, 0x41, 0x00, 0x00, 0x00, 0x42, 0x00]);
        Assert.Equal(ToolResultStatus.Denied, ExcerptStatus(root, file));
    }

    [Fact]
    public void NoBomNul_StaysDenied()
    {
        string root = Fixture();
        string file = Path.Combine(root, "raw-binary.log");
        File.WriteAllBytes(file, "ab\0cd"u8.ToArray());
        Assert.Equal(ToolResultStatus.Denied, ExcerptStatus(root, file));
    }

    private static ToolResultStatus ExcerptStatus(string root, string file)
    {
        var hub = new EvidencePreviewHub();
        using var store = new AgentStore(Path.Combine(root, "agent.db"));
        var broker = new ToolBroker(store);
        broker.Register(new ExcerptTools(hub));
        string id = broker.MintFileId(file);
        var scope = new InvestigationScope("review-excerpt", new[] { root });
        var result = broker.Dispatch(scope,
            new ToolCallRequest("read_text_excerpt", new Dictionary<string, string> { ["file_id"] = id }),
            new InvestigationBudgets(), CancellationToken.None);
        return result.Status;
    }
}
