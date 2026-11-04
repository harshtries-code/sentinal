using Sentinel.App.Services;
using Sentinel.App.ViewModels;
using Sentinel.Engine.Actions;
using Sentinel.Engine.Policy;
using Sentinel.Store;

namespace Sentinel.Tests;

// E33: the Confirm Sheet. The preview lists exactly the files;
// every exclusion names its reason; Confirm approves exactly the
// listed files; progress/cancel/Undo behave; the Cleaner page opens
// the sheet for files and explains group rows honestly.
public sealed class ConfirmSheetTests : IDisposable
{
    private readonly string _root;
    private readonly string _dbPath;
    private bool _disposed;

    public ConfirmSheetTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "sentinel-e33-" + Guid.NewGuid().ToString("N"));
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
            // Best effort: temp cleanup never fails the test.
        }
    }

    private string WriteFile(string name, string content = "vault-me")
    {
        string path = Path.Combine(_root, name);
        File.WriteAllText(path, content);
        return path;
    }

    private sealed class CapturingAudit : IActionAuditSink
    {
        public bool TryAppend(AuditDraft draft, out long seq, out string error)
        {
            seq = 1;
            error = string.Empty;
            return true;
        }
    }

    private sealed class FixedLevels : IPermissionLevels
    {
        private readonly PermissionLevel _cleaner;

        public FixedLevels(PermissionLevel cleaner)
        {
            _cleaner = cleaner;
        }

        public PermissionLevel LevelFor(string module) =>
            module == "Cleaner" ? _cleaner : PermissionLevel.L0;
    }

    private sealed class FakeExecutor : IActionExecutor
    {
        public BatchExecutionRequest? Seen { get; private set; }

        public Func<BatchExecutionRequest, BatchExecutionResult>? Handler { get; set; }

        public Task<BatchExecutionResult> ExecuteAsync(
            BatchExecutionRequest request, CancellationToken ct)
        {
            Seen = request;
            if (Handler is not null)
            {
                return Task.FromResult(Handler(request));
            }

            var items = request.Approval.Targets
                .Select(t => new ItemOutcome(t, ItemStatus.Done, "fake moved", "Ok", "V-x", true))
                .ToList();
            return Task.FromResult(new BatchExecutionResult(BatchStatus.Completed, items, null));
        }
    }

    private sealed class HangingExecutor : IActionExecutor
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<BatchExecutionResult> ExecuteAsync(
            BatchExecutionRequest request, CancellationToken ct)
        {
            Started.SetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, ct);
            throw new InvalidOperationException("unreachable");
        }
    }

    private sealed class FakeUndo : IUndoService
    {
        public List<string> SeenRefs { get; } = [];

        public Func<IReadOnlyList<string>, IReadOnlyList<UndoItemResult>>? Handler { get; set; }

        public Task<IReadOnlyList<UndoItemResult>> RestoreAsync(
            IReadOnlyList<string> vaultRefs, CancellationToken ct)
        {
            SeenRefs.AddRange(vaultRefs);
            IReadOnlyList<UndoItemResult> results = Handler is null
                ? vaultRefs.Select(v => new UndoItemResult(v, true, "restored", @"C:\orig")).ToList()
                : Handler(vaultRefs);
            return Task.FromResult(results);
        }
    }

    private sealed class FakeHost : IConfirmSheetHost
    {
        public List<ConfirmSheetViewModel> Shown { get; } = [];

        public void Show(ConfirmSheetViewModel sheet) => Shown.Add(sheet);
    }

    private static ActionDispatcher DispatcherWith(
        PermissionLevel cleaner, IActionExecutor? executor = null)
    {
        var dispatcher = new ActionDispatcher(new CapturingAudit(), new FixedLevels(cleaner));
        if (executor is not null)
        {
            Assert.True(dispatcher.RegisterExecutor("clean_items_to_vault", executor));
        }

        return dispatcher;
    }

    private static CleanPreview PreviewFor(params string[] paths) =>
        CleanPreviewBuilder.BuildPreview(
            paths.Select(p => (p, "safe")).ToList(),
            new RiskClassifier(), DateTime.UtcNow, 9, ["C:\\"], null);

    private static ConfirmSheetViewModel SheetFor(
        CleanPreview preview, ActionDispatcher dispatcher, FakeUndo? undo = null) =>
        new(preview, ActionRegistry.Find("clean_items_to_vault")!,
            () => dispatcher, undo ?? new FakeUndo(), ["C:\\excluded"]);

    private static async Task SpinUntilAsync(Func<bool> cond, string what)
    {
        for (int i = 0; i < 200 && !cond(); i++)
        {
            await Task.Delay(25);
        }

        Assert.True(cond(), what);
    }

    [Fact]
    public void Preview_EmptySelection_Refused()
    {
        var preview = CleanPreviewBuilder.BuildPreview(
            [], new RiskClassifier(), DateTime.UtcNow, 1, [_root], null);
        Assert.NotNull(preview.RefusedReason);
        Assert.Contains("Nothing is selected", preview.RefusedReason);
        Assert.Empty(preview.Included);
    }

    [Fact]
    public void Preview_OverCap_Refused()
    {
        var many = Enumerable.Range(0, CleanPreviewBuilder.MaxPreviewItems + 1)
            .Select(i => (Path.Combine(_root, $"missing-{i}.tmp"), "safe"))
            .ToList();
        var preview = CleanPreviewBuilder.BuildPreview(
            many, new RiskClassifier(), DateTime.UtcNow, 1, [_root], null);
        Assert.NotNull(preview.RefusedReason);
        Assert.Contains("Too many items", preview.RefusedReason);
    }

    [Fact]
    public void Preview_AtCap_NoCapRefusal()
    {
        var many = Enumerable.Range(0, CleanPreviewBuilder.MaxPreviewItems)
            .Select(i => (Path.Combine(_root, $"missing-{i}.tmp"), "safe"))
            .ToList();
        var preview = CleanPreviewBuilder.BuildPreview(
            many, new RiskClassifier(), DateTime.UtcNow, 1, [_root], null);
        Assert.NotNull(preview.RefusedReason);
        Assert.DoesNotContain("Too many", preview.RefusedReason);
    }

    [Fact]
    public void Preview_SafeFile_IncludedWithLiveFingerprint()
    {
        string path = WriteFile("junk.tmp");
        var info = new FileInfo(path);

        var preview = PreviewFor(path);

        Assert.Null(preview.RefusedReason);
        var item = Assert.Single(preview.Included);
        Assert.Equal(path, item.Path);
        Assert.Equal("junk.tmp", item.Name);
        Assert.Equal(info.Length, item.SizeBytes);
        Assert.Equal(info.LastWriteTimeUtc.Ticks, item.MtimeUtcTicks);
        Assert.Equal(RiskTier.Safe, item.Tier);
        Assert.StartsWith("ui-", item.BrokerId);
        Assert.NotEmpty(item.TierReasons);
        Assert.Empty(preview.Excluded);
        Assert.Equal(info.Length, preview.TotalBytes);
    }

    [Fact]
    public void Preview_VerifiedOrphan_IncludedAsReview()
    {
        string path = WriteFile("orphan.dll");
        var classifier = new RiskClassifier(
            windows: @"C:\Windows", programFiles: _root, programFilesX86: @"C:\PFx86",
            programData: @"C:\PD", temp: @"C:\Temp", localAppData: @"C:\LAD",
            roamingAppData: @"C:\RAD", userDataRoots: [], neverList: []);

        var preview = CleanPreviewBuilder.BuildPreview(
            [(path, "review")], classifier, DateTime.UtcNow, 1, [_root],
            _ => true);

        var item = Assert.Single(preview.Included);
        Assert.Equal(RiskTier.Review, item.Tier);
    }

    [Fact]
    public void Preview_NeverList_ExcludedProtected()
    {
        string path = WriteFile("never.tmp");
        var classifier = new RiskClassifier(neverList: [_root]);

        var preview = CleanPreviewBuilder.BuildPreview(
            [(path, "safe")], classifier, DateTime.UtcNow, 1, [_root], null);

        Assert.Empty(preview.Included);
        var excluded = Assert.Single(preview.Excluded);
        Assert.Contains("Protected", excluded.Reason);
        Assert.NotNull(preview.RefusedReason);
    }

    [Fact]
    public void Preview_DeadShortcut_WithFlags_IncludedAsReview()
    {
        string path = WriteFile("dead.lnk");
        var preview = CleanPreviewBuilder.BuildPreview(
            [(path, "review")], new RiskClassifier(), DateTime.UtcNow, 1, [_root], null,
            _ => FingerprintAttrs.DeadShortcut);

        var item = Assert.Single(preview.Included);
        Assert.Equal(RiskTier.Review, item.Tier);
    }

    [Fact]
    public void Preview_DeadShortcut_WithoutFlags_FallsBackToLiveStat()
    {
        // No-evidence fallback: without the scan flags a dead link
        // reads as its live-stat tier. Production always passes the
        // DB lookup (CleanerViewModel.BeginVaultAction), so this
        // documents the fallback, not the product path.
        string path = WriteFile("dead2.lnk");
        var preview = PreviewFor(path);

        var item = Assert.Single(preview.Included);
        Assert.Equal(RiskTier.Safe, item.Tier);
    }

    [Fact]
    public void Preview_MissingFile_Excluded()
    {
        var preview = PreviewFor(Path.Combine(_root, "gone.tmp"));

        Assert.Empty(preview.Included);
        Assert.Contains("Cannot be read", preview.Excluded[0].Reason);
    }

    [Fact]
    public void Preview_Directory_Excluded()
    {
        var preview = CleanPreviewBuilder.BuildPreview(
            [(_root, "safe")], new RiskClassifier(), DateTime.UtcNow, 1, [_root], null);

        Assert.Empty(preview.Included);
        Assert.Contains("folder", preview.Excluded[0].Reason);
    }

    [Fact]
    public void Preview_OfflineFile_Excluded()
    {
        string path = WriteFile("offline.tmp");
        File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.Offline);
        try
        {
            Assert.True(FileFlags.IsOffline(File.GetAttributes(path)),
                "The filesystem refused the Offline bit; placeholder branch untested.");
            var preview = PreviewFor(path);

            Assert.Empty(preview.Included);
            Assert.Contains("placeholder", preview.Excluded[0].Reason);
        }
        finally
        {
            File.SetAttributes(path, File.GetAttributes(path) & ~FileAttributes.Offline);
        }
    }

    [Fact]
    public void Preview_LockedFile_Excluded()
    {
        string path = WriteFile("locked.tmp");
        using var hold = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        var preview = PreviewFor(path);

        Assert.Empty(preview.Included);
        Assert.Contains("another program", preview.Excluded[0].Reason);
    }

    [Theory]
    [InlineData("duplicates", "keeper")]
    [InlineData("orphans", "file-by-file")]
    [InlineData("apps", "never vaulted as a unit")]
    [InlineData("never-touch", "Protected")]
    [InlineData("bogus-mix", "not vaultable")]
    public void Preview_GroupMixes_ExcludedWithReasons(string mix, string word)
    {
        string path = WriteFile($"group-{mix}.tmp");
        var preview = CleanPreviewBuilder.BuildPreview(
            [(path, mix)], new RiskClassifier(), DateTime.UtcNow, 1, [_root], null);

        Assert.Empty(preview.Included);
        Assert.Contains(word, preview.Excluded[0].Reason);
    }

    [Fact]
    public void Preview_BrokerIds_Unique()
    {
        string a = WriteFile("a.tmp");
        string b = WriteFile("b.tmp");
        var preview = PreviewFor(a, b);

        Assert.Equal(2, preview.Included.Count);
        Assert.NotEqual(preview.Included[0].BrokerId, preview.Included[1].BrokerId);
    }

    [Fact]
    public void Preview_FlagsLookupThrows_FallsBack()
    {
        string path = WriteFile("throwflags.tmp");
        int Boom(string p) => throw new IOException("db hiccup");
        var preview = CleanPreviewBuilder.BuildPreview(
            [(path, "safe")], new RiskClassifier(), DateTime.UtcNow, 1, [_root], null, Boom);

        Assert.Single(preview.Included);
    }

    [Fact]
    public async Task Sheet_Confirm_BuildsApprovalFromPreview()
    {
        string path = WriteFile("confirm.tmp");
        var preview = PreviewFor(path);
        var executor = new FakeExecutor();
        var sheet = SheetFor(preview, DispatcherWith(PermissionLevel.L2, executor));

        await sheet.RunAsync();

        Assert.True(sheet.IsDone);
        Assert.False(sheet.IsRunning);
        Assert.Equal("Completed", sheet.OutcomeTitle);
        Assert.NotNull(executor.Seen);
        Assert.Equal("clean_items_to_vault", executor.Seen.Approval.TemplateId);
        var target = Assert.Single(executor.Seen.Approval.Targets);
        Assert.Equal(path, target.ExpectedPath);
        Assert.Equal(RiskTier.Safe, target.ApprovedTier);
        Assert.Equal(new FileInfo(path).Length, target.ExpectedSize);
        Assert.Equal(["C:\\"], executor.Seen.Approval.ScopeRoots);
        Assert.Equal(["C:\\excluded"], executor.Seen.Approval.ScopeExcluded);
        Assert.Equal(9, executor.Seen.Approval.Generation);
        Assert.Equal(ActionActors.User, executor.Seen.Approval.Actor);
        Assert.NotEmpty(executor.Seen.Approval.IdempotencyKey);
        Assert.True(sheet.UndoAvailable);
        var row = Assert.Single(sheet.ItemResults);
        Assert.Equal("Moved to Vault", row.StatusText);
    }

    [Fact]
    public async Task Sheet_UndoGating_MissingRecord_HidesUndo()
    {
        string path = WriteFile("norecord.tmp");
        var executor = new FakeExecutor
        {
            Handler = req => new BatchExecutionResult(BatchStatus.Completed,
                req.Approval.Targets.Select(t =>
                    new ItemOutcome(t, ItemStatus.Done, "moved, record lost", "Ok", null, false)).ToList(),
                null),
        };
        var sheet = SheetFor(PreviewFor(path), DispatcherWith(PermissionLevel.L2, executor));

        await sheet.RunAsync();

        Assert.True(sheet.IsDone);
        Assert.False(sheet.UndoAvailable);
    }

    [Fact]
    public async Task Sheet_UndoGating_PartialAllMovedVerified_ShowsUndo()
    {
        string a = WriteFile("p-a.tmp");
        string b = WriteFile("p-b.tmp");
        var executor = new FakeExecutor
        {
            Handler = req =>
            {
                var items = new List<ItemOutcome>
                {
                    new(req.Approval.Targets[0], ItemStatus.Done, "moved", "Ok", "V-1", true),
                    new(req.Approval.Targets[1], ItemStatus.Failed, "disk hiccup", null, null, false),
                };
                return new BatchExecutionResult(BatchStatus.Partial, items, null);
            },
        };
        var sheet = SheetFor(PreviewFor(a, b), DispatcherWith(PermissionLevel.L2, executor));

        await sheet.RunAsync();

        Assert.Equal("Partially completed", sheet.OutcomeTitle);
        Assert.True(sheet.UndoAvailable);
        Assert.Equal(2, sheet.ItemResults.Count);
    }

    [Fact]
    public async Task Sheet_UndoGating_OneMovedWithoutRecord_HidesUndo()
    {
        string a = WriteFile("m-a.tmp");
        string b = WriteFile("m-b.tmp");
        var executor = new FakeExecutor
        {
            Handler = req =>
            {
                var items = new List<ItemOutcome>
                {
                    new(req.Approval.Targets[0], ItemStatus.Done, "moved", "Ok", "V-1", true),
                    new(req.Approval.Targets[1], ItemStatus.Done, "moved", "Ok", "V-2", false),
                };
                return new BatchExecutionResult(BatchStatus.Completed, items, null);
            },
        };
        var sheet = SheetFor(PreviewFor(a, b), DispatcherWith(PermissionLevel.L2, executor));

        await sheet.RunAsync();

        Assert.False(sheet.UndoAvailable);
    }

    [Fact]
    public async Task Sheet_Refusal_SurfacesVerbatim()
    {
        string path = WriteFile("refused.tmp");
        var executor = new FakeExecutor();
        var sheet = SheetFor(PreviewFor(path), DispatcherWith(PermissionLevel.L1, executor));

        await sheet.RunAsync();

        Assert.Equal("Refused", sheet.OutcomeTitle);
        Assert.Contains("L1", sheet.OutcomeDetail);
        Assert.Empty(sheet.ItemResults);
        Assert.False(sheet.UndoAvailable);
        Assert.Null(executor.Seen);
    }

    [Fact]
    public async Task Sheet_ExecutorCancelled_MapsToCancelled()
    {
        string path = WriteFile("cancelled.tmp");
        var executor = new FakeExecutor
        {
            Handler = _ => throw new OperationCanceledException(),
        };
        var sheet = SheetFor(PreviewFor(path), DispatcherWith(PermissionLevel.L2, executor));

        await sheet.RunAsync();

        Assert.Equal("Cancelled", sheet.OutcomeTitle);
    }

    [Fact]
    public async Task Sheet_CancelButton_CancelsRun()
    {
        string path = WriteFile("cancelbtn.tmp");
        var hanging = new HangingExecutor();
        var sheet = SheetFor(PreviewFor(path), DispatcherWith(PermissionLevel.L2, hanging));

        sheet.ConfirmCommand.Execute(null);
        await hanging.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(sheet.IsRunning);
        sheet.CancelRunCommand.Execute(null);

        await SpinUntilAsync(() => sheet.IsDone, "cancelled run never finished");
        Assert.Equal("Cancelled", sheet.OutcomeTitle);
    }

    [Fact]
    public async Task Sheet_Progress_Updates()
    {
        string path = WriteFile("progress.tmp");
        var executor = new FakeExecutor
        {
            Handler = req =>
            {
                req.Progress?.Report(new ExecutionProgress(1, 1, "progress.tmp"));
                return new BatchExecutionResult(BatchStatus.Completed,
                    req.Approval.Targets.Select(t =>
                        new ItemOutcome(t, ItemStatus.Done, "moved", "Ok", "V-1", true)).ToList(),
                    null);
            },
        };
        var sheet = SheetFor(PreviewFor(path), DispatcherWith(PermissionLevel.L2, executor));

        await sheet.RunAsync();
        await SpinUntilAsync(() => sheet.ProgressValue == 1, "progress never arrived");

        Assert.Contains("progress.tmp", sheet.ProgressText);
    }

    [Fact]
    public async Task Sheet_Undo_RestoresAndReports()
    {
        string a = WriteFile("u-a.tmp");
        string b = WriteFile("u-b.tmp");
        var executor = new FakeExecutor
        {
            Handler = req => new BatchExecutionResult(BatchStatus.Completed,
                req.Approval.Targets.Select((t, i) =>
                    new ItemOutcome(t, ItemStatus.Done, "moved", "Ok", "V-" + (i + 1), true)).ToList(),
                null),
        };
        var undo = new FakeUndo();
        var sheet = SheetFor(PreviewFor(a, b), DispatcherWith(PermissionLevel.L2, executor), undo);

        await sheet.RunAsync();
        Assert.True(sheet.UndoAvailable);
        await sheet.UndoAsync();

        Assert.Equal(["V-1", "V-2"], undo.SeenRefs.OrderBy(v => v).ToList());
        Assert.Contains("Restored 2 files", sheet.UndoLine);
        Assert.False(sheet.UndoAvailable);
    }

    [Fact]
    public async Task Sheet_Undo_SendsOnlyRestorableRefs()
    {
        string a = WriteFile("r-a.tmp");
        string b = WriteFile("r-b.tmp");
        var executor = new FakeExecutor
        {
            Handler = req => new BatchExecutionResult(BatchStatus.Partial,
            [
                new(req.Approval.Targets[0], ItemStatus.Done, "moved", "Ok", "V-keep", true),
                new(req.Approval.Targets[1], ItemStatus.Failed, "hiccup", null, null, false),
            ], null),
        };
        var undo = new FakeUndo();
        var sheet = SheetFor(PreviewFor(a, b), DispatcherWith(PermissionLevel.L2, executor), undo);

        await sheet.RunAsync();
        await sheet.UndoAsync();

        Assert.Equal(["V-keep"], undo.SeenRefs);
    }

    [Fact]
    public async Task Sheet_Undo_Failure_Surfaces()
    {
        string path = WriteFile("u-fail.tmp");
        var undo = new FakeUndo
        {
            Handler = refs => refs.Select(v =>
                new UndoItemResult(v, false, "vault copy missing", null)).ToList(),
        };
        var sheet = SheetFor(
            PreviewFor(path), DispatcherWith(PermissionLevel.L2, new FakeExecutor()), undo);

        await sheet.RunAsync();
        await sheet.UndoAsync();

        Assert.Contains("Restore failed", sheet.UndoLine);
    }

    [Fact]
    public void Sheet_RefusedPreview_DisablesConfirm()
    {
        var preview = CleanPreviewBuilder.BuildPreview(
            [], new RiskClassifier(), DateTime.UtcNow, 1, [_root], null);
        var sheet = SheetFor(preview, DispatcherWith(PermissionLevel.L2));

        Assert.True(sheet.IsRefusedPreview);
        Assert.False(sheet.ConfirmCommand.CanExecute(null));
        Assert.Contains("Nothing is selected", sheet.RefusedReason);
    }

    [Fact]
    public void Sheet_StaticLines()
    {
        string path = WriteFile("lines.tmp");
        var preview = PreviewFor(path);
        var sheet = SheetFor(preview, DispatcherWith(PermissionLevel.L2));

        Assert.Contains("1 file(s)", sheet.CountLine);
        Assert.Contains("generation 9", sheet.AsOfLine);
        Assert.Contains(@"C:\", sheet.ScopeLine);
        Assert.Contains("Everything selected", sheet.ExcludedLine);
        Assert.False(sheet.HasExcluded);
        Assert.Contains("Vault record", sheet.BackupLine);
        Assert.Contains("L2", sheet.PermissionLine);
        Assert.Contains("no administrator", sheet.ElevationLine);
        Assert.Contains("free no disk space", sheet.LimitationsLine);
    }

    [Fact]
    public void Sheet_ScopeLine_Summarizes()
    {
        string path = WriteFile("scope.tmp");
        var preview = CleanPreviewBuilder.BuildPreview(
            [(path, "safe")], new RiskClassifier(), DateTime.UtcNow, 1,
            [@"C:\a", @"C:\b", @"D:\c", @"E:\d", @"F:\e"], null);
        var sheet = SheetFor(preview, DispatcherWith(PermissionLevel.L2));

        Assert.Contains("+2 more", sheet.ScopeLine);

        var empty = CleanPreviewBuilder.BuildPreview(
            [(path, "safe")], new RiskClassifier(), DateTime.UtcNow, 1, [], null);
        var emptySheet = SheetFor(empty, DispatcherWith(PermissionLevel.L2));
        Assert.Contains("none recorded", emptySheet.ScopeLine);
    }

    private StorageRow FileRow(string path, string tier)
    {
        var info = new FileInfo(path);
        return new StorageRow(
            StorageRowKind.File, Path.GetFileName(path), _root,
            info.Length + " bytes", info.Length, "Junk", tier, true,
            new StorageDetail(path, info.Length + " bytes", "now", "none",
                tier, "know", "verify", "evidence", [], null));
    }

    [Fact]
    public void Cleaner_NoServices_HonestLine_NoSheet()
    {
        var host = new FakeHost();
        var model = new CleanerViewModel(() => null!, () => []);

        model.BeginVaultAction();

        Assert.Contains("aren't wired", model.ActionStatusLine);
        Assert.Empty(host.Shown);
        Assert.False(model.IsActionAvailable);
    }

    [Fact]
    public void Cleaner_EmptySelection_Line_NoSheet()
    {
        var host = new FakeHost();
        var model = new CleanerViewModel(() => null!, () => [],
            new CleanerActionServices(
                () => DispatcherWith(PermissionLevel.L2), new FakeUndo(), host, []));

        model.BeginVaultAction();

        Assert.Equal("Nothing selected.", model.ActionStatusLine);
        Assert.Empty(host.Shown);
    }

    [Fact]
    public void Cleaner_CheckedFiles_OpenSheetWithPreview()
    {
        string a = WriteFile("sheet-a.tmp");
        string b = WriteFile("sheet-b.tmp");
        var host = new FakeHost();
        using var db = new SentinelDb(_dbPath);
        var model = new CleanerViewModel(() => new SentinelDb(_dbPath), () => [],
            new CleanerActionServices(
                () => DispatcherWith(PermissionLevel.L2), new FakeUndo(), host, [_root]));

        var rowA = FileRow(a, "SAFE");
        var rowB = FileRow(b, "REVIEW");
        model.TrackRow(rowA);
        model.TrackRow(rowB);
        model.Rows.Add(rowA);
        model.Rows.Add(rowB);
        rowA.IsSelected = true;
        rowB.IsSelected = true;

        model.BeginVaultAction();

        Assert.Contains("Confirm Sheet opened for 2 file(s)", model.ActionStatusLine);
        var sheet = Assert.Single(host.Shown);
        Assert.Equal(2, sheet.Preview.Included.Count);
        Assert.True(sheet.Preview.Included.All(i => i.Tier is RiskTier.Safe or RiskTier.Review));
    }

    [Fact]
    public void Cleaner_MixedSelection_FilesPlusExplainedGroups()
    {
        string a = WriteFile("mix-a.tmp");
        string sub = Path.Combine(_root, "orphan-dir");
        Directory.CreateDirectory(sub);
        var host = new FakeHost();
        var model = new CleanerViewModel(() => new SentinelDb(_dbPath), () => [],
            new CleanerActionServices(
                () => DispatcherWith(PermissionLevel.L2), new FakeUndo(), host, []));

        var file = FileRow(a, "SAFE");
        var orphan = new StorageRow(
            StorageRowKind.Orphan, "orphan-dir", _root, "1 MB", 1000,
            "Leftover", string.Empty, true,
            new StorageDetail(sub, "1 MB", "old", "none", "tier", "know", "verify", "evidence", [], null));
        model.TrackRow(file);
        model.TrackRow(orphan);
        model.Rows.Add(file);
        model.Rows.Add(orphan);
        file.IsSelected = true;
        orphan.IsSelected = true;

        model.BeginVaultAction();

        // D44: the empty orphan dir expands to a no-files note (not
        // the old "open the folder" exclusion); the file proceeds.
        var sheet = Assert.Single(host.Shown);
        Assert.Single(sheet.Preview.Included);
        var excluded = Assert.Single(sheet.Preview.Excluded);
        Assert.Contains("No inventoried files", excluded.Reason);
        Assert.Contains("Expanded 0 duplicate set(s) and 1 leftover folder(s)", model.ActionStatusLine);
    }

    [Fact]
    public async Task UnavailableUndoService_FailsWithReason()
    {
        var undo = new UnavailableUndoService();
        var results = await undo.RestoreAsync(["V-1"], CancellationToken.None);

        var single = Assert.Single(results);
        Assert.False(single.Restored);
        Assert.Contains("not wired", single.Detail);
    }
}
