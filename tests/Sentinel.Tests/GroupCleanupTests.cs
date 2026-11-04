using System.Security.Cryptography;
using System.Text;
using Sentinel.App.Services;
using Sentinel.App.ViewModels;
using Sentinel.Engine.Actions;
using Sentinel.Engine.Policy;
using Sentinel.Store;

namespace Sentinel.Tests;

// D44: orphan + duplicate cleanup through the existing lawful
// template. Group rows expand to EXPLICIT files (keepers and
// folders ride as notes, never targets); every file still flows
// through classification, the confirm sheet, execution
// revalidation, and proven restore. The fixture test at the end is
// the D44 proof: fake game/browser/orphan cleanup with the apps
// verifiably intact afterwards and every byte restorable.
public sealed class GroupCleanupTests : IDisposable
{
    private readonly string _root;
    private readonly string _dbPath;
    private bool _disposed;

    public GroupCleanupTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "sentinel-d44-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
        _dbPath = Path.Combine(_root, "inv.db");
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
        }
    }

    private string WriteFile(string rel, string content)
    {
        string path = Path.Combine(_root, rel);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    private static string Sha256Hex(string content)
    {
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(content));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static void FingerprintFile(SentinelDb db, string path, string content)
    {
        var info = new FileInfo(path);
        db.UpsertFingerprint(path, info.Length, info.LastWriteTimeUtc.Ticks,
            Sha256Hex(content), 1);
    }

    private static GroupExpansion.DuplicateInputs Inputs(
        IReadOnlyList<string>? preferred = null) =>
        new(preferred ?? [], null, []);

    private sealed class FakeHost : IConfirmSheetHost
    {
        public List<ConfirmSheetViewModel> Shown { get; } = [];

        public void Show(ConfirmSheetViewModel sheet) => Shown.Add(sheet);
    }

    private sealed class CapturingAudit : IActionAuditSink
    {
        public List<AuditDraft> Drafts { get; } = [];

        public bool TryAppend(AuditDraft draft, out long seq, out string error)
        {
            Drafts.Add(draft);
            seq = Drafts.Count;
            error = string.Empty;
            return true;
        }
    }

    private sealed class FixedLevels : IPermissionLevels
    {
        public PermissionLevel LevelFor(string module) =>
            module == "Cleaner" ? PermissionLevel.L2 : PermissionLevel.L0;
    }

    private sealed class FakeUndo : IUndoService
    {
        public Task<IReadOnlyList<UndoItemResult>> RestoreAsync(
            IReadOnlyList<string> vaultRefs, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<UndoItemResult>>([]);
    }

    private static StorageRow DupRow(string memberPath) =>
        new(StorageRowKind.Duplicate, "dup set", Path.GetDirectoryName(memberPath) ?? "",
            "1 KB spare", 1000, "Duplicate", string.Empty, true,
            new StorageDetail(memberPath, "1 KB", "old", "hash", "tier", "know",
                "verify", "evidence", [], null));

    private static StorageRow OrphanRow(string dir) =>
        new(StorageRowKind.Orphan, "orphan-dir", Path.GetDirectoryName(dir) ?? "",
            "—", 0, "Orphan", string.Empty, true,
            new StorageDetail(dir, "—", "Unknown", "Not applicable",
                "Possible leftover — no uninstall entry", "signals",
                "Whether the owning app is really gone.", "Inventory record", [], null));

    // ---- duplicate expansion ----

    [Fact]
    public void DupExpand_SparesListed_KeeperStays()
    {
        string keeper = WriteFile(Path.Combine("app", "data.dat"), "SAME-BYTES");
        string spare1 = WriteFile(Path.Combine("d1", "copy.dat"), "SAME-BYTES");
        string spare2 = WriteFile(Path.Combine("d2", "copy.dat"), "SAME-BYTES");
        using var db = new SentinelDb(_dbPath);
        FingerprintFile(db, keeper, "SAME-BYTES");
        FingerprintFile(db, spare1, "SAME-BYTES");
        FingerprintFile(db, spare2, "SAME-BYTES");

        var expanded = GroupExpansion.ExpandDuplicateSet(db, spare1,
            Inputs([Path.Combine(_root, "app")]), 5000);

        Assert.Equal(2, expanded.Files.Count);
        Assert.DoesNotContain(expanded.Files, f => f.Path == keeper);
        Assert.All(expanded.Files, f => Assert.Equal("review", f.Mix));
        Assert.Equal([keeper], expanded.KeeperPaths);
        Assert.Contains(expanded.Notes, n => n.Path == keeper && n.Reason.Contains("Keeper"));
        Assert.Equal(1, expanded.SetsExpanded);
        Assert.False(expanded.Truncated);
    }

    [Fact]
    public void DupExpand_KeeperMissing_HoldsWholeSet()
    {
        string keeper = WriteFile(Path.Combine("app", "data.dat"), "SAME-BYTES");
        string spare1 = WriteFile(Path.Combine("d1", "copy.dat"), "SAME-BYTES");
        string spare2 = WriteFile(Path.Combine("d2", "copy.dat"), "SAME-BYTES");
        using var db = new SentinelDb(_dbPath);
        FingerprintFile(db, keeper, "SAME-BYTES");
        FingerprintFile(db, spare1, "SAME-BYTES");
        FingerprintFile(db, spare2, "SAME-BYTES");
        File.Delete(keeper);

        var expanded = GroupExpansion.ExpandDuplicateSet(db, spare1,
            Inputs([Path.Combine(_root, "app")]), 5000);

        Assert.Empty(expanded.Files);
        Assert.Empty(expanded.KeeperPaths);
        Assert.Contains(expanded.Notes, n => n.Reason.Contains("only good ones left"));
    }

    [Fact]
    public void DupExpand_ChangedSpare_ExcludedStale()
    {
        string keeper = WriteFile(Path.Combine("app", "data.dat"), "SAME-BYTES");
        string spare1 = WriteFile(Path.Combine("d1", "copy.dat"), "SAME-BYTES");
        string spare2 = WriteFile(Path.Combine("d2", "copy.dat"), "SAME-BYTES");
        using var db = new SentinelDb(_dbPath);
        FingerprintFile(db, keeper, "SAME-BYTES");
        FingerprintFile(db, spare1, "SAME-BYTES");
        FingerprintFile(db, spare2, "SAME-BYTES");
        // spare2 changes after the scan: it left the set.
        File.WriteAllText(spare2, "DIFFERENT-BYTES-NOW");

        var expanded = GroupExpansion.ExpandDuplicateSet(db, spare1,
            Inputs([Path.Combine(_root, "app")]), 5000);

        var file = Assert.Single(expanded.Files);
        Assert.Equal(spare1, file.Path);
        Assert.Contains(expanded.Notes, n => n.Path == spare2 && n.Reason.Contains("Changed since the scan"));
    }

    [Fact]
    public void DupExpand_UninventoriedAnchor_Excluded()
    {
        string ghost = WriteFile(Path.Combine("d1", "ghost.dat"), "GHOST");
        using var db = new SentinelDb(_dbPath);

        var expanded = GroupExpansion.ExpandDuplicateSet(db, ghost, Inputs(), 5000);

        Assert.Empty(expanded.Files);
        Assert.Contains(expanded.Notes, n => n.Reason.Contains("No hashed inventory record"));
    }

    [Fact]
    public void DupExpand_SingleCopy_NothingSpare()
    {
        string only = WriteFile(Path.Combine("d1", "only.dat"), "LONELY");
        using var db = new SentinelDb(_dbPath);
        FingerprintFile(db, only, "LONELY");

        var expanded = GroupExpansion.ExpandDuplicateSet(db, only, Inputs(), 5000);

        Assert.Empty(expanded.Files);
        Assert.Contains(expanded.Notes, n => n.Reason.Contains("Only one copy"));
    }

    [Fact]
    public void DupExpand_Budget_TruncatesWithNote()
    {
        string keeper = WriteFile(Path.Combine("app", "data.dat"), "SAME-BYTES");
        string spare1 = WriteFile(Path.Combine("d1", "copy.dat"), "SAME-BYTES");
        WriteFile(Path.Combine("d2", "copy.dat"), "SAME-BYTES");
        using var db = new SentinelDb(_dbPath);
        FingerprintFile(db, keeper, "SAME-BYTES");
        FingerprintFile(db, spare1, "SAME-BYTES");
        FingerprintFile(db, Path.Combine(_root, "d2", "copy.dat"), "SAME-BYTES");

        var expanded = GroupExpansion.ExpandDuplicateSet(db, spare1,
            Inputs([Path.Combine(_root, "app")]), 1);

        Assert.True(expanded.Truncated);
        Assert.Single(expanded.Files);
        Assert.Contains(expanded.Notes, n => n.Reason.Contains("budget reached"));
    }

    [Fact]
    public void DupExpand_MemberCap_RefusedWhole()
    {
        // 1001 identical copies: the member query caps at 1000, so
        // the keeper cannot be reasoned from the whole set.
        string anchor = string.Empty;
        using (var db = new SentinelDb(_dbPath))
        {
            for (int i = 0; i < 1001; i++)
            {
                string p = WriteFile(Path.Combine("mass", $"c{i}.dat"), "MASS-BYTES");
                FingerprintFile(db, p, "MASS-BYTES");
                anchor = p;
            }
        }

        using var reopen = new SentinelDb(_dbPath);
        var expanded = GroupExpansion.ExpandDuplicateSet(reopen, anchor, Inputs(), 5000);

        Assert.True(expanded.Truncated);
        Assert.Empty(expanded.Files);
        Assert.Contains(expanded.Notes, n => n.Reason.Contains("1000+ copies"));
    }

    // ---- orphan expansion ----

    [Fact]
    public void OrphanExpand_FilesListed_DirNoted()
    {
        string dir = Path.Combine(_root, "orphan", "OldApp");
        string a = WriteFile(Path.Combine("orphan", "OldApp", "old.dll"), "OLD-DLL");
        string b = WriteFile(Path.Combine("orphan", "OldApp", "readme.txt"), "OLD-README");
        using var db = new SentinelDb(_dbPath);
        FingerprintFile(db, a, "OLD-DLL");
        FingerprintFile(db, b, "OLD-README");

        var expanded = GroupExpansion.ExpandOrphanDir(db, dir, 5000);

        Assert.Equal(2, expanded.Files.Count);
        Assert.DoesNotContain(expanded.Files, f => f.Path == dir);
        Assert.Contains(expanded.Notes, n => n.Path == dir && n.Reason.Contains("file-by-file only"));
        Assert.Equal(1, expanded.SetsExpanded);
    }

    [Fact]
    public void OrphanExpand_EmptyDir_Noted()
    {
        string dir = Path.Combine(_root, "orphan", "Empty");
        Directory.CreateDirectory(dir);
        using var db = new SentinelDb(_dbPath);

        var expanded = GroupExpansion.ExpandOrphanDir(db, dir, 5000);

        Assert.Empty(expanded.Files);
        Assert.Contains(expanded.Notes, n => n.Reason.Contains("No inventoried files"));
    }

    [Fact]
    public void OrphanExpand_UninventoriedLiveFile_Ignored()
    {
        string dir = Path.Combine(_root, "orphan", "Mixed");
        string known = WriteFile(Path.Combine("orphan", "Mixed", "known.dll"), "KNOWN");
        WriteFile(Path.Combine("orphan", "Mixed", "mystery.dll"), "MYSTERY");
        using var db = new SentinelDb(_dbPath);
        FingerprintFile(db, known, "KNOWN");

        var expanded = GroupExpansion.ExpandOrphanDir(db, dir, 5000);

        var file = Assert.Single(expanded.Files);
        Assert.Equal(known, file.Path);
    }

    [Fact]
    public void OrphanExpand_Budget_Truncates()
    {
        string dir = Path.Combine(_root, "orphan", "Big");
        using var db = new SentinelDb(_dbPath);
        for (int i = 0; i < 3; i++)
        {
            string p = WriteFile(Path.Combine("orphan", "Big", $"f{i}.dat"), $"BYTES-{i}");
            FingerprintFile(db, p, $"BYTES-{i}");
        }

        var expanded = GroupExpansion.ExpandOrphanDir(db, dir, 2);

        Assert.True(expanded.Truncated);
        Assert.Equal(2, expanded.Files.Count);
        Assert.Contains(expanded.Notes, n => n.Reason.Contains("budget reached"));
    }

    // ---- Cleaner wiring ----

    private CleanerViewModel ModelWith(FakeHost host, Func<string[]>? never = null)
    {
        var dispatcher = new ActionDispatcher(new CapturingAudit(), new FixedLevels());
        return new CleanerViewModel(
            () => new SentinelDb(_dbPath),
            never ?? (() => []),
            new CleanerActionServices(() => dispatcher, new FakeUndo(), host, []));
    }

    [Fact]
    public void Cleaner_DuplicateRow_ExpandsToSparesWithKeeperNote()
    {
        // The ViewModel uses live ProgramFiles roots, so keeper
        // determinism comes from mtime: the keeper is newest.
        string keeper = WriteFile(Path.Combine("app", "data.dat"), "SAME-BYTES");
        string spare = WriteFile(Path.Combine("d1", "copy.dat"), "SAME-BYTES");
        File.SetLastWriteTimeUtc(spare, DateTime.UtcNow.AddDays(-2));
        File.SetLastWriteTimeUtc(keeper, DateTime.UtcNow.AddDays(-1));
        using (var db = new SentinelDb(_dbPath))
        {
            FingerprintFile(db, keeper, "SAME-BYTES");
            FingerprintFile(db, spare, "SAME-BYTES");
        }

        var host = new FakeHost();
        var model = ModelWith(host);
        var row = DupRow(spare);
        model.TrackRow(row);
        model.Rows.Add(row);
        row.IsSelected = true;

        model.BeginVaultAction();

        var sheet = Assert.Single(host.Shown);
        var included = Assert.Single(sheet.Preview.Included);
        Assert.Equal(spare, included.Path);
        Assert.Contains(sheet.Preview.Excluded, e => e.Path == keeper && e.Reason.Contains("Keeper"));
        Assert.Contains("Expanded 1 duplicate set(s)", model.ActionStatusLine);
    }

    [Fact]
    public void Cleaner_OrphanRow_ExpandsToFiles()
    {
        string dir = Path.Combine(_root, "orphan", "OldApp");
        string a = WriteFile(Path.Combine("orphan", "OldApp", "old.dll"), "OLD-DLL");
        WriteFile(Path.Combine("orphan", "OldApp", "readme.txt"), "OLD-README");
        using (var db = new SentinelDb(_dbPath))
        {
            FingerprintFile(db, a, "OLD-DLL");
            FingerprintFile(db, Path.Combine(_root, "orphan", "OldApp", "readme.txt"), "OLD-README");
        }

        var host = new FakeHost();
        var model = ModelWith(host);
        var row = OrphanRow(dir);
        model.TrackRow(row);
        model.Rows.Add(row);
        row.IsSelected = true;

        model.BeginVaultAction();

        var sheet = Assert.Single(host.Shown);
        Assert.Equal(2, sheet.Preview.Included.Count);
        Assert.Contains(sheet.Preview.Excluded, e => e.Path == dir && e.Reason.Contains("file-by-file only"));
        Assert.Contains("Expanded 0 duplicate set(s) and 1 leftover folder(s)", model.ActionStatusLine);
    }

    [Fact]
    public void Cleaner_ProtectedSpare_ExcludedNever()
    {
        string keeper = WriteFile(Path.Combine("app", "data.dat"), "SAME-BYTES");
        string spare = WriteFile(Path.Combine("prot", "copy.dat"), "SAME-BYTES");
        string guarded = Path.Combine(_root, "prot");
        File.SetLastWriteTimeUtc(spare, DateTime.UtcNow.AddDays(-2));
        File.SetLastWriteTimeUtc(keeper, DateTime.UtcNow.AddDays(-1));
        using (var db = new SentinelDb(_dbPath))
        {
            FingerprintFile(db, keeper, "SAME-BYTES");
            FingerprintFile(db, spare, "SAME-BYTES");
        }

        var host = new FakeHost();
        var model = ModelWith(host, () => [guarded]);
        var row = DupRow(spare);
        model.TrackRow(row);
        model.Rows.Add(row);
        row.IsSelected = true;

        model.BeginVaultAction();

        var sheet = Assert.Single(host.Shown);
        Assert.Empty(sheet.Preview.Included);
        Assert.Contains(sheet.Preview.Excluded,
            e => e.Path == spare && e.Reason.Contains("Never Touch"));
        Assert.NotNull(sheet.Preview.RefusedReason);
    }

    // ---- registry pin ----

    [Fact]
    public void Registry_HasNoActionTemplate_RemainsInformational()
    {
        // Uninstall registry leftovers are findings, never targets:
        // no template may name the registry as something it acts on.
        foreach (var template in ActionRegistry.All)
        {
            Assert.DoesNotContain("regist", template.Id, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("regist", template.Title, StringComparison.OrdinalIgnoreCase);
        }

        // The app-group backstop still routes to manual uninstall.
        string path = WriteFile("appgroup.tmp", "app-group-probe");
        var preview = CleanPreviewBuilder.BuildPreview(
            [(path, "apps")], new RiskClassifier(), DateTime.UtcNow, 1, [_root], null);
        Assert.Contains("uninstall the app", preview.Excluded[0].Reason);
    }

    // ---- the D44 fixture proof ----

    [Fact]
    public async Task Fixture_FakeAppGameBrowser_RoundTrip()
    {
        // Fake world: a game (exe + data + saves), a browser
        // profile, spare copies, a leftover dir, and one spare
        // under Never Touch. Byte contents are the "works" oracle.
        string gameDir = Path.Combine(_root, "fx", "game");
        string browserDir = Path.Combine(_root, "fx", "browser", "Profile");
        string orphanDir = Path.Combine(_root, "fx", "orphan", "OldApp");
        string guardedDir = Path.Combine(_root, "fx", "guarded");
        DateTime now = DateTime.UtcNow;

        string gameExe = WriteFile(Path.Combine("fx", "game", "Game.exe"), "EXE-BYTES");
        string gameDat = WriteFile(Path.Combine("fx", "game", "Data", "game.dat"), "GAME-DATA-A");
        string saveDat = WriteFile(Path.Combine("fx", "game", "Saves", "save.dat"), "SAVE-PROGRESS");
        string dup1 = WriteFile(Path.Combine("fx", "dup1", "copy.dat"), "GAME-DATA-A");
        string dup2 = WriteFile(Path.Combine("fx", "dup2", "copy.dat"), "GAME-DATA-A");
        string loginDat = WriteFile(Path.Combine("fx", "browser", "Profile", "Login Data"), "LOGIN-ROWS");
        string dup3 = WriteFile(Path.Combine("fx", "dup3", "logincopy.dat"), "LOGIN-ROWS");
        string oldDll = WriteFile(Path.Combine("fx", "orphan", "OldApp", "old.dll"), "OLD-DLL");
        string readme = WriteFile(Path.Combine("fx", "orphan", "OldApp", "readme.txt"), "OLD-README");
        string guardedSpare = WriteFile(Path.Combine("fx", "guarded", "copy.dat"), "GAME-DATA-A");

        // Keepers newest, so the live-roots table agrees: game.dat
        // and Login Data stay.
        foreach (var p in new[] { dup1, dup2, dup3, guardedSpare, oldDll, readme })
        {
            File.SetLastWriteTimeUtc(p, now.AddDays(-3));
        }

        File.SetLastWriteTimeUtc(gameExe, now.AddDays(-2));
        File.SetLastWriteTimeUtc(saveDat, now.AddDays(-2));
        File.SetLastWriteTimeUtc(gameDat, now.AddDays(-1));
        File.SetLastWriteTimeUtc(loginDat, now.AddDays(-1));

        var originals = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in new[] { gameExe, gameDat, saveDat, dup1, dup2, loginDat, dup3, oldDll, readme, guardedSpare })
        {
            originals[p] = Sha256Hex(File.ReadAllText(p));
        }

        using (var db = new SentinelDb(_dbPath))
        {
            foreach (var p in originals.Keys)
            {
                FingerprintFile(db, p, File.ReadAllText(p));
            }
        }

        var host = new FakeHost();
        var audit = new CapturingAudit();
        var dispatcher = new ActionDispatcher(audit, new FixedLevels());
        string vaultDir = Path.Combine(_root, "vault");
        Directory.CreateDirectory(vaultDir);
        var vault = new VaultStore(Path.Combine(vaultDir, "vault.db"));
        try
        {
            var executor = new CleanExecutor(
                () => vault, new DiskVaultFileIO(), Path.Combine(vaultDir, "files"),
                () => new RiskClassifier([guardedDir]),
                new StaticEvidenceSignerReader(), audit,
                () => new SentinelDb(_dbPath));
            Assert.True(dispatcher.RegisterExecutor("clean_items_to_vault", executor));

            var model = new CleanerViewModel(
                () => new SentinelDb(_dbPath),
                () => [guardedDir],
                new CleanerActionServices(() => dispatcher, new FakeUndo(), host, []));
            var dupRowA = DupRow(dup1);
            var dupRowB = DupRow(dup3);
            var orphRow = OrphanRow(orphanDir);
            model.TrackRow(dupRowA);
            model.TrackRow(dupRowB);
            model.TrackRow(orphRow);
            model.Rows.Add(dupRowA);
            model.Rows.Add(dupRowB);
            model.Rows.Add(orphRow);
            dupRowA.IsSelected = true;
            dupRowB.IsSelected = true;
            orphRow.IsSelected = true;

            model.BeginVaultAction();

            var sheet = Assert.Single(host.Shown);
            var included = sheet.Preview.Included.Select(i => i.Path).OrderBy(p => p).ToList();
            Assert.Equal(
                new[] { dup1, dup2, dup3, oldDll, readme }.OrderBy(p => p).ToList(),
                included);
            // Keepers + guarded spare + orphan dir ride as notes.
            Assert.Contains(sheet.Preview.Excluded, e => e.Path == gameDat && e.Reason.Contains("Keeper"));
            Assert.Contains(sheet.Preview.Excluded, e => e.Path == loginDat && e.Reason.Contains("Keeper"));
            Assert.Contains(sheet.Preview.Excluded,
                e => e.Path == guardedSpare && e.Reason.Contains("Never Touch"));
            Assert.Contains(sheet.Preview.Excluded,
                e => e.Path == orphanDir && e.Reason.Contains("file-by-file only"));

            // Run the REAL executor over the sheet's exact file
            // list (the sheet's own approval-building is E33-covered;
            // scope behavior is E31's domain — the approval carries
            // the fixture root as its scope here).
            var approval = new ActionApproval("clean_items_to_vault",
                sheet.Preview.Included.Select(i => new ActionTarget(
                    "t:" + i.BrokerId, i.Path, "file", i.Tier,
                    i.SizeBytes, i.MtimeUtcTicks, null)).ToList(),
                [_root], [], 1, DateTimeOffset.UtcNow, ActionActors.User,
                Guid.NewGuid().ToString("N"));
            var outcome = await dispatcher.DispatchAsync(approval, null, CancellationToken.None);

            Assert.Equal(BatchStatus.Completed, outcome.Status);
            Assert.Equal(5, outcome.Items.Count);
            Assert.All(outcome.Items, i => Assert.Equal(ItemStatus.Done, i.Status));

            // Vaulted originals are gone; every app/browser/user byte
            // is untouched — the fake game and browser "still work".
            foreach (var p in new[] { dup1, dup2, dup3, oldDll, readme })
            {
                Assert.False(File.Exists(p), p + " should be vaulted");
            }

            foreach (var p in new[] { gameExe, gameDat, saveDat, loginDat, guardedSpare })
            {
                Assert.True(File.Exists(p), p + " should be intact");
                Assert.Equal(originals[p], Sha256Hex(File.ReadAllText(p)));
            }

            Assert.Equal(5, vault.ListRestorable().Count);

            // Full restore: every byte back, hashes equal.
            var undo = new VaultUndoService(
                () => vault, new DiskVaultFileIO(), Path.Combine(vaultDir, "files"), audit);
            var refs = vault.ListRestorable().Select(v => v.Id).ToList();
            var restored = await undo.RestoreAsync(refs, CancellationToken.None);

            Assert.All(restored, r => Assert.True(r.Restored, r.Detail));
            foreach (var p in new[] { dup1, dup2, dup3, oldDll, readme })
            {
                Assert.True(File.Exists(p), p + " should be restored");
                Assert.Equal(originals[p], Sha256Hex(File.ReadAllText(p)));
            }

            Assert.Empty(vault.ListRestorable());
        }
        finally
        {
            vault.Dispose();
        }
    }
}
