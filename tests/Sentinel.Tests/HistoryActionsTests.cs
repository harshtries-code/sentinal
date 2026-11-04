using System.Text.Json;
using Sentinel.App.Services;
using Sentinel.App.ViewModels;
using Sentinel.Engine.Actions;
using Sentinel.Store;

namespace Sentinel.Tests;

// E37: action history + vault UI. Real audit/vault stores seeded on
// temp paths; the timeline, drawer, integrity line, vault rows,
// conflict notes, review lines, recovery banner, restore flow, and
// exports all read them. Serviceless construction keeps the original
// honest empty states.
public sealed class HistoryActionsTests : IDisposable
{
    private readonly string _root;
    private bool _disposed;

    public HistoryActionsTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "sentinel-e37-" + Guid.NewGuid().ToString("N"));
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

    private string TempPath(string name) => Path.Combine(_root, name);

    private HistoryViewModel ModelWith(
        string auditDb, string vaultDb, string vaultFiles, int reviewDays = 30) =>
        new(
            () => new SentinelDb(TempPath("scan.db")),
            () => new AgentStore(TempPath("agent.db")),
            new HistoryActionServices(
                () => new ActionAuditLog(auditDb, "t", "m", "p"),
                () => new VaultStore(vaultDb),
                new VaultUndoService(
                    () => new VaultStore(vaultDb), new DiskVaultFileIO(), vaultFiles,
                    new AuditLogSink(() => new ActionAuditLog(auditDb, "t", "m", "p"))),
                () => reviewDays,
                vaultFiles));

    private static long SeedAudit(
        string path, string detail, string actor = "user",
        string action = "clean_items_to_vault", string undo = "NotApplicable")
    {
        using var log = new ActionAuditLog(path, "t", "m", "p");
        return log.Append(DateTime.UtcNow.ToString("o"), actor, action, "[\"f:1\"]",
            null, string.Empty, "{}", "Vault:V-1", undo, detail);
    }

    [Fact]
    public void NoServices_PreservesHonestEmpty()
    {
        var vm = new HistoryViewModel(() => null!, () => null!);

        Assert.Contains("Vault is empty", vm.VaultState);
        vm.SelectedKind = "Actions";
        Assert.Contains("don't change", vm.EmptyText);
        Assert.Equal("Integrity verification unavailable", vm.AuditIntegrityLine);
        Assert.Empty(vm.VaultRows);
        Assert.False(vm.HasRecovery);
    }

    [Fact]
    public void Actions_AppearInTimeline_WithTitlesKindsSources()
    {
        string audit = TempPath("a1.db");
        SeedAudit(audit, "[Completed] Moved all 2 file(s) to the Vault.");
        SeedAudit(audit, "[Refused/TemplateUnknown] 'x' is not a known action.", actor: "scheduled");
        SeedAudit(audit, "[Undo] Restored 1 file.", actor: "agent-proposed+user-approved", undo: "Undone");

        var vm = ModelWith(audit, TempPath("v1.db"), TempPath("vf1"));
        vm.Refresh();

        vm.SelectedKind = "Actions";
        var actions = vm.Groups.SelectMany(g => g.Events).ToList();
        Assert.Equal(3, actions.Count);
        Assert.All(actions, e => Assert.Equal("Action", e.Kind));
        Assert.Contains(actions, e => e.Title == "Vault move completed" && e.StatusKind == "Good");
        Assert.Contains(actions, e => e.Title == "Vault move refused" && e.StatusKind == "Neutral");
        Assert.Contains(actions, e => e.Title == "Restored from Vault" && e.StatusKind == "Good");
        Assert.Contains(actions, e => e.Source == "You");
        Assert.Contains(actions, e => e.Source == "Scheduled run");
        Assert.Contains(actions, e => e.Source == "AI proposed · you approved");

        vm.SelectedKind = "All types";
        Assert.Equal(3, vm.Groups.SelectMany(g => g.Events).Count());

        vm.SelectedKind = "Scans";
        Assert.Empty(vm.Groups.SelectMany(g => g.Events));
    }

    [Fact]
    public void ActionDrawer_Fields()
    {
        string audit = TempPath("a2.db");
        SeedAudit(audit, "[Completed] Moved all 1 file(s).");

        var vm = ModelWith(audit, TempPath("v2.db"), TempPath("vf2"));
        vm.Refresh();
        vm.SelectedKind = "Actions";
        vm.SelectedEvent = vm.Groups.SelectMany(g => g.Events).First();

        var fields = vm.DrawerFields.ToDictionary(f => f.Label, f => f.Value);
        Assert.Equal("You", fields["Actor"]);
        Assert.Equal("clean_items_to_vault", fields["Action"]);
        Assert.Contains("Moved all 1", fields["What happened"]);
        Assert.Equal("Vault:V-1", fields["Backup"]);
        Assert.Contains("seq 1", fields["Entry"]);
        Assert.Contains("t · model m", fields["Versions"]);
    }

    [Fact]
    public void Integrity_Ok_Line()
    {
        string audit = TempPath("a3.db");
        SeedAudit(audit, "[Completed] done.");

        var vm = ModelWith(audit, TempPath("v3.db"), TempPath("vf3"));
        vm.Refresh();

        Assert.Contains("integrity ok", vm.AuditIntegrityLine.ToLowerInvariant());
        Assert.Contains("tip seq 1", vm.AuditIntegrityLine);
    }

    [Fact]
    public void Integrity_Broken_Line()
    {
        string audit = TempPath("a4.db");
        SeedAudit(audit, "[Completed] one.");
        SeedAudit(audit, "[Completed] two.");
        using (var raw = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={audit}"))
        {
            raw.Open();
            using var cmd = raw.CreateCommand();
            cmd.CommandText = "UPDATE AuditEntries SET AfterJson = 'forged' WHERE Seq = 1;";
            cmd.ExecuteNonQuery();
        }

        var vm = ModelWith(audit, TempPath("v4.db"), TempPath("vf4"));
        vm.Refresh();

        Assert.Contains("BROKEN", vm.AuditIntegrityLine);
        Assert.Contains("seq 1", vm.AuditIntegrityLine);
    }

    [Fact]
    public void Vault_Rows_And_Summary()
    {
        string vaultDb = TempPath("v5.db");
        using (var vault = new VaultStore(vaultDb))
        {
            vault.RecordItem(new VaultItem("V-1", "B", Path.Combine(_root, "a.tmp"),
                "V-1__a.tmp", "C", 100, "sha", DateTime.UtcNow.ToString("o"),
                "clean_items_to_vault", "user", VaultStatus.Quarantined,
                true, null, null, null, string.Empty));
            vault.RecordItem(new VaultItem("V-2", "B", Path.Combine(_root, "b.tmp"),
                "V-2__b.tmp", "C", 50, "sha", DateTime.UtcNow.ToString("o"),
                "clean_items_to_vault", "user", VaultStatus.Restored,
                true, null, "2026-11-04T00:00:00Z", Path.Combine(_root, "b.tmp"), "undo"));
        }

        var vm = ModelWith(TempPath("a5.db"), vaultDb, TempPath("vf5"));
        vm.Refresh();

        Assert.Equal(2, vm.VaultRows.Count);
        var kept = vm.VaultRows.First(r => r.Ref == "V-1");
        Assert.True(kept.CanRestore);
        Assert.True(kept.RestoreCommand.CanExecute(null));
        Assert.Contains("Review due", kept.ReviewLine);
        var restored = vm.VaultRows.First(r => r.Ref == "V-2");
        Assert.False(restored.CanRestore);
        Assert.False(restored.RestoreCommand.CanExecute(null));
        Assert.Equal("Already restored.", restored.ConflictNote);
        Assert.Contains("2 files", vm.VaultState);
        Assert.Contains("retained", vm.VaultState);
        Assert.Contains("never auto-deleted", vm.VaultState);
        Assert.Contains("1 restorable", vm.VaultTitle);
    }

    [Fact]
    public void ConflictNote_Shown_WhenDestinationTaken()
    {
        string original = Path.Combine(_root, "taken.tmp");
        File.WriteAllText(original, "user-data");
        string vaultDb = TempPath("v6.db");
        using (var vault = new VaultStore(vaultDb))
        {
            vault.RecordItem(new VaultItem("V-9", "B", original,
                "V-9__taken.tmp", "C", 9, "sha", DateTime.UtcNow.ToString("o"),
                "clean_items_to_vault", "user", VaultStatus.Quarantined,
                true, null, null, null, string.Empty));
        }

        var vm = ModelWith(TempPath("a6.db"), vaultDb, TempPath("vf6"));
        vm.Refresh();

        var row = Assert.Single(vm.VaultRows);
        Assert.Contains("beside", row.ConflictNote);
        Assert.Contains("(restored 1)", row.ConflictNote);
        Assert.Contains("not be overwritten", row.ConflictNote);
    }

    [Fact]
    public void ReviewLine_Due_And_Overdue_And_NeverDelete()
    {
        var now = new DateTime(2026, 11, 4, 12, 0, 0, DateTimeKind.Utc);
        var fresh = new VaultItem("V-1", "B", @"C:\a", "r", "C", 1, "s",
            now.ToString("o"), "t", "user", VaultStatus.Quarantined,
            true, null, null, null, string.Empty);
        var old = fresh with
        {
            Id = "V-2",
            MovedUtc = now.AddDays(-40).ToString("o"),
        };
        var restored = fresh with
        {
            Id = "V-3",
            Status = VaultStatus.Restored,
            MovedUtc = now.AddDays(-100).ToString("o"),
        };

        Assert.Contains("Review due", HistoryViewModel.ReviewLineFor(fresh, 30, now));
        string overdue = HistoryViewModel.ReviewLineFor(old, 30, now);
        Assert.Contains("overdue by 10 days", overdue);
        Assert.Contains("never auto-deleted", overdue);
        Assert.Equal(string.Empty, HistoryViewModel.ReviewLineFor(restored, 30, now));
        string week = HistoryViewModel.ReviewLineFor(old, 7, now);
        Assert.Contains("overdue by 33 days", week);
    }

    [Fact]
    public async Task Restore_RoundTrip_AppearsInTimeline()
    {
        string original = Path.Combine(_root, "hrestore.tmp");
        string files = TempPath("vf7");
        string rel = "V-21__hrestore.tmp";
        Directory.CreateDirectory(Path.Combine(files, "C"));
        File.WriteAllText(Path.Combine(files, "C", rel), "restore-me");
        string sha;
        using (var stream = File.OpenRead(Path.Combine(files, "C", rel)))
        {
            sha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream));
        }

        string vaultDb = TempPath("v7.db");
        using (var vault = new VaultStore(vaultDb))
        {
            vault.RecordItem(new VaultItem("V-21", "B", original, rel, "C", 10, sha,
                DateTime.UtcNow.ToString("o"), "clean_items_to_vault", "user",
                VaultStatus.Quarantined, true, null, null, null, string.Empty));
        }

        string audit = TempPath("a7.db");
        var vm = ModelWith(audit, vaultDb, files);
        vm.Refresh();
        Assert.Single(vm.VaultRows);

        await vm.RestoreVaultItem("V-21");

        Assert.Contains("original place", vm.VaultNote);
        Assert.Equal("restore-me", File.ReadAllText(original));
        var row = Assert.Single(vm.VaultRows);
        Assert.False(row.CanRestore);
        vm.SelectedKind = "Actions";
        var actions = vm.Groups.SelectMany(g => g.Events).ToList();
        Assert.Contains(actions, e => e.Title == "Restored from Vault");
    }

    [Fact]
    public async Task Restore_NonRestorable_Guarded()
    {
        string vaultDb = TempPath("v8.db");
        using (var vault = new VaultStore(vaultDb))
        {
            vault.RecordItem(new VaultItem("V-30", "B", Path.Combine(_root, "x.tmp"),
                "V-30__x.tmp", "C", 1, "sha", DateTime.UtcNow.ToString("o"),
                "clean_items_to_vault", "user", VaultStatus.InterruptedMove,
                false, null, null, null, "stuck"));
        }

        var vm = ModelWith(TempPath("a8.db"), vaultDb, TempPath("vf8"));
        vm.Refresh();
        var row = Assert.Single(vm.VaultRows);
        Assert.False(row.CanRestore);

        await vm.RestoreVaultItem("V-30");

        Assert.Contains("not restorable", vm.VaultNote);
        await vm.RestoreVaultItem("V-nope");
        Assert.Contains("not restorable", vm.VaultNote);
    }

    [Fact]
    public void Recovery_Surfaces_InBanner()
    {
        string files = TempPath("vf9");
        string rel = "V-40__rec.tmp";
        Directory.CreateDirectory(Path.Combine(files, "C"));
        File.WriteAllText(Path.Combine(files, "C", rel), "recovered");
        string sha;
        using (var stream = File.OpenRead(Path.Combine(files, "C", rel)))
        {
            sha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream));
        }

        string vaultDb = TempPath("v9.db");
        using (var vault = new VaultStore(vaultDb))
        {
            vault.RecordItem(new VaultItem("V-40", "B", Path.Combine(_root, "rec.tmp"),
                rel, "C", 9, sha, DateTime.UtcNow.ToString("o"),
                "clean_items_to_vault", "user", VaultStatus.InterruptedMove,
                false, null, null, null, "crashed mid-move"));
        }

        var vm = ModelWith(TempPath("a9.db"), vaultDb, files);
        vm.Refresh();

        Assert.True(vm.HasRecovery);
        Assert.Contains("Recovered 1 vault record", vm.RecoveryNote);
    }

    [Fact]
    public void ActionError_KeepsScans_VaultEmpty()
    {
        string scanDb = TempPath("scan10.db");
        using (var db = new SentinelDb(scanDb))
        {
            long id = db.Passport.BeginRun(_root, 1, "Balanced");
            db.Passport.EndRun(id, 10, 100, 5, 1000);
        }

        var vm = new HistoryViewModel(
            () => new SentinelDb(scanDb),
            () => new AgentStore(TempPath("agent10.db")),
            new HistoryActionServices(
                () => throw new IOException("audit disk gone"),
                () => new VaultStore(TempPath("v10.db")),
                new UnavailableUndoService(), () => 30, TempPath("vf10")));
        vm.Refresh();

        Assert.Contains("unavailable", vm.ActionErrorLine);
        Assert.Single(vm.Runs);
        Assert.Empty(vm.VaultRows);
    }

    [Fact]
    public void ExportJson_ContainsActionsVaultIntegrity()
    {
        string audit = TempPath("a11.db");
        SeedAudit(audit, "[Completed] Moved hostil\"><e & \"done.");
        string vaultDb = TempPath("v11.db");
        using (var vault = new VaultStore(vaultDb))
        {
            vault.RecordItem(new VaultItem("V-50", "B", Path.Combine(_root, "e.tmp"),
                "V-50__e.tmp", "C", 7, "sha", DateTime.UtcNow.ToString("o"),
                "clean_items_to_vault", "user", VaultStatus.Quarantined,
                true, null, null, null, string.Empty));
        }

        var vm = ModelWith(audit, vaultDb, TempPath("vf11"));
        using var json = JsonDocument.Parse(vm.BuildAuditJson());

        Assert.True(json.RootElement.TryGetProperty("actions", out var actions));
        Assert.Equal(1, actions.GetArrayLength());
        Assert.Contains("hostil", actions[0].GetProperty("detail").GetString());
        Assert.True(json.RootElement.TryGetProperty("vaultItems", out var items));
        Assert.Equal(1, items.GetArrayLength());
        Assert.True(json.RootElement.TryGetProperty("integrity", out var integrity));
        Assert.True(integrity.GetProperty("ok").GetBoolean());
        Assert.True(json.RootElement.TryGetProperty("retainedBytes", out _));
    }

    [Fact]
    public void ExportHtml_ContainsSections_EscapesHostile()
    {
        string audit = TempPath("a12.db");
        SeedAudit(audit, "[Completed] Moved \"><script>alert(1)</script> done.");

        var vm = ModelWith(audit, TempPath("v12.db"), TempPath("vf12"));
        string html = vm.BuildAuditHtml();

        Assert.Contains("Audit integrity", html);
        Assert.Contains("Actions", html);
        Assert.Contains("Vault items", html);
        Assert.Contains("OK —", html);
        Assert.DoesNotContain("<script>", html);
        Assert.Contains("&lt;script&gt;", html);
    }

    [Fact]
    public void Sheet_ViewHistory_InvokesAndCloses()
    {
        var preview = CleanPreviewBuilder.BuildPreview(
            [], new Engine.Policy.RiskClassifier(), DateTime.UtcNow, 1, [], null);
        var sheet = new ConfirmSheetViewModel(
            preview, ActionRegistry.Find("clean_items_to_vault")!,
            () => throw new InvalidOperationException("no dispatch"),
            new UnavailableUndoService(), []);

        Assert.False(sheet.HasViewHistory);
        Assert.False(sheet.ViewHistoryCommand.CanExecute(null));

        bool navigated = false;
        bool closed = false;
        sheet.ViewHistory = () => navigated = true;
        sheet.CloseRequested += () => closed = true;
        Assert.True(sheet.HasViewHistory);

        sheet.ViewHistoryCommand.Execute(null);

        Assert.True(navigated);
        Assert.True(closed);
    }

    [Fact]
    public void Cleaner_PassesViewHistory_ToSheet()
    {
        string path = Path.Combine(_root, "vh.tmp");
        File.WriteAllText(path, "x");
        var host = new CapturingHost();
        bool navigated = false;
        var model = new CleanerViewModel(
            () => new SentinelDb(TempPath("inv13.db")), () => [],
            new CleanerActionServices(
                () => throw new InvalidOperationException("no dispatch"),
                new UnavailableUndoService(), host, [],
                () => navigated = true));

        var row = new StorageRow(
            StorageRowKind.File, "vh.tmp", _root, "1 bytes", 1, "Junk", "SAFE", true,
            new StorageDetail(path, "1 bytes", "now", "none", "t", "k", "v", "e", [], null));
        model.TrackRow(row);
        model.Rows.Add(row);
        row.IsSelected = true;

        model.BeginVaultAction();

        var sheet = Assert.Single(host.Shown);
        Assert.True(sheet.HasViewHistory);
        sheet.ViewHistoryCommand.Execute(null);
        Assert.True(navigated);
    }

    private sealed class CapturingHost : IConfirmSheetHost
    {
        public List<ConfirmSheetViewModel> Shown { get; } = [];

        public void Show(ConfirmSheetViewModel sheet) => Shown.Add(sheet);
    }

    [Fact]
    public void Settings_VaultReviewDays_Sanitize()
    {
        Assert.Equal(30, SentinelSettings.Defaults.VaultReviewDays);
        var wild = SentinelSettings.Defaults with { VaultReviewDays = 5 };
        Assert.Equal(30, wild.Sanitized().VaultReviewDays);
        foreach (int days in new[] { 7, 30, 90 })
        {
            var kept = SentinelSettings.Defaults with { VaultReviewDays = days };
            Assert.Equal(days, kept.Sanitized().VaultReviewDays);
        }

        string legacy = TempPath("legacy14.json");
        File.WriteAllText(legacy, """{"DefaultScanMode":"Balanced"}""");
        Assert.Equal(30, new SettingsStore(legacy).Load().VaultReviewDays);
    }
}
