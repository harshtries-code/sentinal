using Sentinel.App.ViewModels;
using Sentinel.Engine.Actions;
using Sentinel.Engine.Drivers;
using Sentinel.Engine.Policy;
using Sentinel.Engine.SystemInventory;
using Sentinel.Store;

namespace Sentinel.Tests;

// D43: driver dialogs. The preview builders decide (eligible pick,
// OEM-set precedence, unsupported reasons + official link-outs,
// rollback targets); the sheet renders lines + outcomes and never
// says "fixed" for refused/partial/failed runs; the Drivers page
// check flow searches read-only and opens sheets. Live installs
// stay in the VM dangerous-ops battery.
public sealed class DriverDialogTests : IDisposable
{
    private const string DeviceId = @"PCI\VEN_8086&DEV_9BC5\3&11583659&0&10";

    private readonly string _root;

    public DriverDialogTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "sentinel-d43-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch
        {
        }
    }

    // ---- fakes ----

    private sealed class FakeOps : IDriverOps
    {
        public Func<string, DeviceStatus> ReadDeviceFunc { get; set; } =
            _ => new DeviceStatus(true, 0, null, 0, "Intel UHD", "30.0.100.9805",
                "09/25/2021", ["PCI\\VEN_8086&DEV_9BC5"]);

        public List<StorePackage> Store { get; } = [];

        public Func<IReadOnlyList<DriverCandidate>> SearchFunc { get; set; } = () => [];

        public Func<OemScanSet> ScanFunc { get; set; } = () => new OemScanSet([], "no catalogue");

        public DeviceStatus ReadDevice(string deviceId) => ReadDeviceFunc(deviceId);

        public IReadOnlyList<DriverRecord> EnumInstalledDrivers() => [];

        public IReadOnlyList<StorePackage> EnumStore() => Store;

        public IReadOnlyList<DriverCandidate> SearchWindowsUpdate(
            string deviceId, string? deviceName, IReadOnlyList<string> hardwareIds) =>
            SearchFunc();

        public InstallResult InstallWindowsUpdate(string deviceId, string catalogueId) =>
            throw new InvalidOperationException("live install in a dialog test");

        public InstallResult InstallStorePackage(string publishedInf) =>
            throw new InvalidOperationException("live install in a dialog test");

        public OemScanSet ScanOemCatalogue() => ScanFunc();

        public InstallResult ApplyOemCatalogue() =>
            throw new InvalidOperationException("live install in a dialog test");

        public bool IsNetworkAvailable() => true;
    }

    private sealed class FakeSr : ISrClient
    {
        public (long? Sequence, string? Error) Begin(string description) => (7, null);

        public string? End(long sequence) => null;
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
        private readonly Dictionary<string, PermissionLevel> _levels;

        public FixedLevels(Dictionary<string, PermissionLevel> levels)
        {
            _levels = levels;
        }

        public PermissionLevel LevelFor(string module) =>
            _levels.TryGetValue(module, out var level) ? level : PermissionLevel.L0;
    }

    private sealed class FakeExecutor : IActionExecutor
    {
        public Func<BatchExecutionRequest, BatchExecutionResult>? Handler { get; set; }

        public List<ActionApproval> Seen { get; } = [];

        public Task<BatchExecutionResult> ExecuteAsync(
            BatchExecutionRequest request, CancellationToken ct)
        {
            Seen.Add(request.Approval);
            if (Handler is not null)
            {
                return Task.FromResult(Handler(request));
            }

            var items = request.Approval.Targets
                .Select(t => new ItemOutcome(t, ItemStatus.Done, "fake done", null, null, false))
                .ToList();
            return Task.FromResult(new BatchExecutionResult(BatchStatus.Completed, items, "fake"));
        }
    }

    private sealed class CapturingHost : IDriverSheetHost
    {
        public List<DriverSheetViewModel> Shown { get; } = [];

        public void Show(DriverSheetViewModel sheet) => Shown.Add(sheet);
    }

    // ---- builders ----

    private static DriverCandidate WuCandidate(
        string version = "31.0.101.2121",
        string catalogueId = "cat-1",
        string? signer = "Windows Update") =>
        new(DriverSource.WindowsUpdate, null, version, null, signer,
            ["PCI\\VEN_8086&DEV_9BC5"], catalogueId, null);

    private static LadderResolution WuOnlyLadder() =>
        new([new LadderStep(DriverSource.WindowsUpdate, null, "WU first.")], []);

    private static LadderResolution FullLadder() =>
        new([
            new LadderStep(DriverSource.WindowsUpdate, null, "WU first."),
            new LadderStep(DriverSource.OemCatalogue, "dell", "DCU catalogue."),
            new LadderStep(DriverSource.VendorLinkOut, "intel", "Intel page (link only)."),
        ], []);

    private static DriverPreviewDevice PreviewDevice(
        IReadOnlyList<DriverCandidate>? wu = null,
        LadderResolution? ladder = null,
        string? installed = "30.0.100.9805") =>
        new(DeviceId, "Intel UHD", installed, "09/25/2021",
            ["PCI\\VEN_8086&DEV_9BC5"], ladder ?? WuOnlyLadder(), wu ?? []);

    private DriverBlocklist NewBlocklist(string name)
    {
        string path = Path.Combine(_root, name);
        return new DriverBlocklist(() => new PassportDb(path));
    }

    private static ActionTemplate UpdateTemplate() =>
        ActionRegistry.All.First(t => t.Id == "driver_update_from_ladder");

    private static ActionTemplate RollbackTemplate() =>
        ActionRegistry.All.First(t => t.Id == "driver_rollback");

    private static DeviceRow SelectedRow() =>
        new("Intel UHD", "30.0.100.9805", "Intel", "Working", "Working", false,
            new DeviceDetail(DeviceId, "30.0.100.9805", "Intel", "test", "now"));

    // ---- preview: update picks ----

    [Fact]
    public void Preview_EligibleCandidate_IncludedWithReason()
    {
        var preview = DriverPreviewBuilder.Build(
            [PreviewDevice([WuCandidate()])], null, new HashSet<string>(), true);

        Assert.Null(preview.RefusedReason);
        var item = Assert.Single(preview.Included);
        Assert.Equal("31.0.101.2121", item.Candidate.Version);
        Assert.Contains("Newer than installed", item.WhyEligible);
        Assert.Empty(preview.Unsupported);
    }

    [Fact]
    public void Preview_FirstEligibleWins_BlockedSkipped()
    {
        var blocked = new HashSet<string> { "WindowsUpdate|31.0.101.1111" };
        var preview = DriverPreviewBuilder.Build(
            [PreviewDevice([WuCandidate("31.0.101.1111", "cat-old"), WuCandidate()])],
            null, blocked, true);

        var item = Assert.Single(preview.Included);
        Assert.Equal("cat-1", item.Candidate.CatalogueId);
    }

    [Fact]
    public void Preview_NoCandidates_UnsupportedWithoutGuesses()
    {
        var preview = DriverPreviewBuilder.Build(
            [PreviewDevice([], FullLadder())], null, new HashSet<string>(), true);

        Assert.Empty(preview.Included);
        var unsupported = Assert.Single(preview.Unsupported);
        Assert.Contains("no driver", unsupported.Reason);
        var link = Assert.Single(unsupported.LinkOuts);
        Assert.Equal("Intel", link.VendorName);
        Assert.StartsWith("https://", link.Url);
        Assert.NotNull(preview.RefusedReason);
    }

    [Fact]
    public void Preview_IneligibleCandidates_CarriesVerdict()
    {
        var preview = DriverPreviewBuilder.Build(
            [PreviewDevice([WuCandidate("29.0.0.0")])], null, new HashSet<string>(), true);

        Assert.Empty(preview.Included);
        var unsupported = Assert.Single(preview.Unsupported);
        Assert.Contains("older than installed", unsupported.Reason);
    }

    [Fact]
    public void Preview_UnversionedCandidate_HonestReason()
    {
        var preview = DriverPreviewBuilder.Build(
            [PreviewDevice([WuCandidate(version: string.Empty)])], null, new HashSet<string>(), true);

        Assert.Empty(preview.Included);
        var unsupported = Assert.Single(preview.Unsupported);
        Assert.Contains("blind install", unsupported.Reason);
        Assert.DoesNotContain("older than installed", unsupported.Reason);
    }

    [Fact]
    public void Preview_UnknownInstalledVersion_RefusedPerDevice()
    {
        var preview = DriverPreviewBuilder.Build(
            [PreviewDevice([WuCandidate()], installed: null)], null, new HashSet<string>(), true);

        Assert.Empty(preview.Included);
        var unsupported = Assert.Single(preview.Unsupported);
        Assert.Contains("rollback point", unsupported.Reason);
    }

    [Fact]
    public void Preview_Unelevated_RefusedWithRelaunch()
    {
        var preview = DriverPreviewBuilder.Build(
            [PreviewDevice([WuCandidate()])], null, new HashSet<string>(), false);

        // Still decided (the sheet shows what WOULD run) but refused.
        Assert.Single(preview.Included);
        Assert.NotNull(preview.RefusedReason);
        Assert.Contains("relaunch Sentinel as administrator", preview.RefusedReason);
    }

    [Fact]
    public void Preview_OemSet_OfferedOnlyWithoutWuRows()
    {
        var scan = new OemScanSet(["BIOS 1.2.3"], "1 update");
        var preview = DriverPreviewBuilder.Build(
            [PreviewDevice([], FullLadder())], scan, new HashSet<string>(), true);

        Assert.NotNull(preview.OemSet);
        Assert.Equal("dell", preview.OemSet.VendorId);
        Assert.Equal(["BIOS 1.2.3"], preview.OemSet.Titles);
        Assert.Equal([DeviceId], preview.OemSet.DeviceIds);
        Assert.Null(preview.RefusedReason);
    }

    [Fact]
    public void Preview_OemSet_NeverBundledWithWuRows()
    {
        var scan = new OemScanSet(["BIOS 1.2.3"], "1 update");
        var preview = DriverPreviewBuilder.Build(
            [PreviewDevice([WuCandidate()], FullLadder())], scan, new HashSet<string>(), true);

        Assert.Single(preview.Included);
        Assert.Null(preview.OemSet);
        Assert.NotNull(preview.OemNote);
        Assert.Contains("never bundled", preview.OemNote);
    }

    [Fact]
    public void Preview_OemScanWithoutLadderStep_Ignored()
    {
        var scan = new OemScanSet(["BIOS 1.2.3"], "1 update");
        var preview = DriverPreviewBuilder.Build(
            [PreviewDevice([], WuOnlyLadder())], scan, new HashSet<string>(), true);

        Assert.Null(preview.OemSet);
        Assert.Null(preview.OemNote);
    }

    // ---- preview: rollback ----

    private static StorePackage StorePkg(string published, string version) =>
        new(published, "orig.inf", "Intel Corporation", "Display", "{g}",
            version, "Microsoft Windows Hardware Compatibility Publisher", null);

    private static DeviceHistoryRow HistoryRow(long id, string? version) =>
        new(id, "2026-11-01T00:00:00Z", DeviceId, "Intel UHD", 0, "Working", version);

    [Fact]
    public void RollbackPreview_OlderOnRecord_MatchedToStore()
    {
        var preview = DriverPreviewBuilder.BuildRollback(
            [new DriverRollbackRequest(DeviceId, "Intel UHD", "PCI\\VEN_8086&DEV_9BC5", "31.0.101.2121")],
            _ => [HistoryRow(2, "31.0.101.2121"), HistoryRow(1, "30.0.100.9805")],
            [StorePkg("oem12.inf", "09/25/2021 30.0.100.9805")],
            true);

        Assert.Null(preview.RefusedReason);
        var item = Assert.Single(preview.Included);
        Assert.Equal("31.0.101.2121", item.BadVersion);
        Assert.Equal("30.0.100.9805", item.PreviousVersion);
        Assert.Equal("oem12.inf", item.TargetInf);
        Assert.Equal("unknown", item.BadSource);
    }

    [Fact]
    public void RollbackPreview_NoOlderVersion_Unsupported()
    {
        var preview = DriverPreviewBuilder.BuildRollback(
            [new DriverRollbackRequest(DeviceId, "Intel UHD", null, "31.0.101.2121")],
            _ => [HistoryRow(1, "31.0.101.2121")],
            [StorePkg("oem12.inf", "09/25/2021 30.0.100.9805")],
            true);

        Assert.Empty(preview.Included);
        var unsupported = Assert.Single(preview.Unsupported);
        Assert.Contains("No earlier driver version is on record", unsupported.Reason);
        Assert.NotNull(preview.RefusedReason);
    }

    [Fact]
    public void RollbackPreview_PreviousLeftStore_Unsupported()
    {
        var preview = DriverPreviewBuilder.BuildRollback(
            [new DriverRollbackRequest(DeviceId, "Intel UHD", null, "31.0.101.2121")],
            _ => [HistoryRow(1, "30.0.100.9805")],
            [StorePkg("oem45.inf", "01/10/2022 31.0.101.2121")],
            true);

        Assert.Empty(preview.Included);
        var unsupported = Assert.Single(preview.Unsupported);
        Assert.Contains("30.0.100.9805", unsupported.Reason);
    }

    [Fact]
    public void RollbackPreview_HistoryUnreadable_Unsupported()
    {
        var preview = DriverPreviewBuilder.BuildRollback(
            [new DriverRollbackRequest(DeviceId, "Intel UHD", null, "31.0.101.2121")],
            _ => throw new InvalidOperationException("db locked"),
            [StorePkg("oem12.inf", "09/25/2021 30.0.100.9805")],
            true);

        var unsupported = Assert.Single(preview.Unsupported);
        Assert.Contains("could not be read", unsupported.Reason);
    }

    [Fact]
    public void RollbackPreview_Unelevated_Refused()
    {
        var preview = DriverPreviewBuilder.BuildRollback(
            [new DriverRollbackRequest(DeviceId, "Intel UHD", null, "31.0.101.2121")],
            _ => [HistoryRow(1, "30.0.100.9805")],
            [StorePkg("oem12.inf", "09/25/2021 30.0.100.9805")],
            false);

        Assert.Single(preview.Included);
        Assert.Contains("relaunch Sentinel as administrator", preview.RefusedReason);
    }

    // ---- sheet: lines + approval ----

    private static ActionDispatcher DispatcherWith(FakeExecutor executor)
    {
        var dispatcher = new ActionDispatcher(new CapturingAudit(), new FixedLevels(
            new Dictionary<string, PermissionLevel> { ["Drivers"] = PermissionLevel.L2 }));
        Assert.True(dispatcher.RegisterExecutor("driver_update_from_ladder", executor));
        Assert.True(dispatcher.RegisterExecutor("driver_rollback", executor));
        return dispatcher;
    }

    [Fact]
    public void Sheet_Lines_NameBackupAndScope()
    {
        var preview = DriverPreviewBuilder.Build(
            [PreviewDevice([WuCandidate()])], null, new HashSet<string>(), true);
        var sheet = new DriverSheetViewModel(preview, UpdateTemplate(), () => null!);

        Assert.Contains("restore point", sheet.BackupLine);
        Assert.Contains("automatically reinstalls", sheet.BackupLine);
        Assert.Contains("Drivers L2", sheet.PermissionLine);
        Assert.Contains("exactly", sheet.PermissionLine);
        Assert.Contains("never restarts your PC", sheet.RestartLine);
        Assert.Contains("verified after it lands", sheet.LimitationsLine);
        Assert.Equal("1 device(s) to update", sheet.CountLine);
        var row = Assert.Single(sheet.Included);
        Assert.Equal("30.0.100.9805 → 31.0.101.2121", row.ChangeLine);
        Assert.Contains("Windows Update", row.SourceLine);
    }

    [Fact]
    public void Sheet_RollbackLines_NameTarget()
    {
        var preview = DriverPreviewBuilder.BuildRollback(
            [new DriverRollbackRequest(DeviceId, "Intel UHD", null, "31.0.101.2121")],
            _ => [HistoryRow(1, "30.0.100.9805")],
            [StorePkg("oem12.inf", "09/25/2021 30.0.100.9805")],
            true);
        var sheet = new DriverSheetViewModel(preview, RollbackTemplate(), () => null!);

        Assert.Equal("1 device(s) to roll back", sheet.CountLine);
        var row = Assert.Single(sheet.Included);
        Assert.Equal("31.0.101.2121 → 30.0.100.9805", row.ChangeLine);
        Assert.Contains("oem12.inf", row.SourceLine);
        Assert.Contains("blocked", row.DetailLine);
        Assert.Contains("verifies the bad version is gone", sheet.LimitationsLine);
    }

    [Fact]
    public void Sheet_RefusedPreview_DisablesConfirm()
    {
        var preview = DriverPreviewBuilder.Build(
            [PreviewDevice([WuCandidate()])], null, new HashSet<string>(), false);
        var sheet = new DriverSheetViewModel(preview, UpdateTemplate(), () => null!);

        Assert.True(sheet.IsRefusedPreview);
        Assert.False(sheet.ConfirmCommand.CanExecute(null));
    }

    [Fact]
    public async Task Sheet_Run_BuildsDeviceApprovalWithAux()
    {
        var preview = DriverPreviewBuilder.Build(
            [PreviewDevice([WuCandidate()])], null, new HashSet<string>(), true);
        var executor = new FakeExecutor();
        var dispatcher = DispatcherWith(executor);
        var sheet = new DriverSheetViewModel(preview, UpdateTemplate(), () => dispatcher);

        await sheet.RunAsync();

        Assert.True(sheet.IsDone);
        var approval = Assert.Single(executor.Seen);
        Assert.Equal("driver_update_from_ladder", approval.TemplateId);
        var target = Assert.Single(approval.Targets);
        Assert.Equal("device", target.Kind);
        Assert.Equal(DeviceId, target.ExpectedPath);
        Assert.Equal(RiskTier.Review, target.ApprovedTier);
        var aux = DriverTargetAux.Parse(target.AuxJson);
        Assert.NotNull(aux);
        Assert.Equal("windows-update", aux.CandidateSource);
        Assert.Equal("31.0.101.2121", aux.CandidateVersion);
        Assert.Equal("cat-1", aux.CandidateCatalogueId);
    }

    [Fact]
    public async Task Sheet_OemRun_BuildsOemAux()
    {
        var scan = new OemScanSet(["BIOS 1.2.3"], "1 update");
        var preview = DriverPreviewBuilder.Build(
            [PreviewDevice([], FullLadder())], scan, new HashSet<string>(), true);
        var executor = new FakeExecutor();
        var sheet = new DriverSheetViewModel(preview, UpdateTemplate(), () => DispatcherWith(executor));

        Assert.Equal("1 catalogue update(s) for 1 device(s) — one set", sheet.CountLine);
        await sheet.RunAsync();

        var target = Assert.Single(Assert.Single(executor.Seen).Targets);
        var aux = DriverTargetAux.Parse(target.AuxJson);
        Assert.NotNull(aux);
        Assert.Equal("oem-catalogue", aux.CandidateSource);
    }

    [Fact]
    public async Task Sheet_RollbackRun_BuildsRollbackAux()
    {
        var preview = DriverPreviewBuilder.BuildRollback(
            [new DriverRollbackRequest(DeviceId, "Intel UHD", null, "31.0.101.2121")],
            _ => [HistoryRow(1, "30.0.100.9805")],
            [StorePkg("oem12.inf", "09/25/2021 30.0.100.9805")],
            true);
        var executor = new FakeExecutor();
        var sheet = new DriverSheetViewModel(preview, RollbackTemplate(), () => DispatcherWith(executor));

        await sheet.RunAsync();

        var approval = Assert.Single(executor.Seen);
        Assert.Equal("driver_rollback", approval.TemplateId);
        var aux = DriverTargetAux.Parse(Assert.Single(approval.Targets).AuxJson);
        Assert.NotNull(aux);
        Assert.Equal("oem12.inf", aux.TargetPublishedInf);
        Assert.Equal("31.0.101.2121", aux.BadVersion);
        Assert.Equal("30.0.100.9805", aux.PreviousVersion);
    }

    // ---- sheet: outcome titles (the never-"fixed" rule) ----

    private static DriverSheetViewModel SheetFor(
        DriverPreview preview, FakeExecutor executor) =>
        new(preview, UpdateTemplate(), () => DispatcherWith(executor));

    private static void AssertNoFixedWord(params string[] texts)
    {
        foreach (var text in texts)
        {
            Assert.DoesNotContain("fixed", text ?? string.Empty, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("repaired", text ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task Sheet_RefusedOutcome_SaysNoChangesMade()
    {
        var preview = DriverPreviewBuilder.Build(
            [PreviewDevice([WuCandidate()])], null, new HashSet<string>(), true);
        var executor = new FakeExecutor
        {
            Handler = request => new BatchExecutionResult(
                BatchStatus.Refused,
                request.Approval.Targets
                    .Select(t => new ItemOutcome(t, ItemStatus.Refused, "stale", null, null, false))
                    .ToList(),
                "refused"),
        };
        var sheet = SheetFor(preview, executor);

        await sheet.RunAsync();

        Assert.Equal("No changes made", sheet.OutcomeTitle);
        var row = Assert.Single(sheet.ItemResults);
        Assert.Equal("Skipped", row.StatusText);
        Assert.Equal(string.Empty, sheet.RestartStateLine);
        AssertNoFixedWord(sheet.OutcomeTitle, sheet.OutcomeDetail, row.StatusText, row.Detail);
    }

    [Fact]
    public async Task Sheet_PartialOutcome_NeverBlanketFixed()
    {
        var preview = DriverPreviewBuilder.Build(
            [PreviewDevice([WuCandidate()])], null, new HashSet<string>(), true);
        var executor = new FakeExecutor
        {
            Handler = request => new BatchExecutionResult(
                BatchStatus.Partial,
                [
                    new ItemOutcome(request.Approval.Targets[0], ItemStatus.Done,
                        "Updated 30.x → 31.y via Windows Update and verified. Restore point RestorePoint:1.", null, null, true),
                ],
                "partial"),
        };
        var sheet = SheetFor(preview, executor);

        await sheet.RunAsync();

        Assert.Equal("Partially completed", sheet.OutcomeTitle);
        AssertNoFixedWord(sheet.OutcomeTitle, sheet.OutcomeDetail);
        Assert.All(sheet.ItemResults, r => AssertNoFixedWord(r.StatusText, r.Detail));
        Assert.Contains("roll it back from the Drivers page", sheet.RollbackHintLine);
    }

    [Fact]
    public async Task Sheet_FailedOutcome_SaysFailedSafely()
    {
        var preview = DriverPreviewBuilder.Build(
            [PreviewDevice([WuCandidate()])], null, new HashSet<string>(), true);
        var executor = new FakeExecutor
        {
            Handler = request => new BatchExecutionResult(
                BatchStatus.Failed,
                request.Approval.Targets
                    .Select(t => new ItemOutcome(t, ItemStatus.Failed,
                        "Verification failed: still on 30.x. The previous driver was automatically reinstalled.",
                        "Verify/Failed", null, false))
                    .ToList(),
                "failed"),
        };
        var sheet = SheetFor(preview, executor);

        await sheet.RunAsync();

        Assert.Equal("Failed safely", sheet.OutcomeTitle);
        var row = Assert.Single(sheet.ItemResults);
        Assert.Equal("Failed", row.StatusText);
        AssertNoFixedWord(sheet.OutcomeTitle, sheet.OutcomeDetail, row.StatusText, row.Detail);
    }

    [Fact]
    public async Task Sheet_CompletedOutcome_NamesRebootEvidence()
    {
        var preview = DriverPreviewBuilder.Build(
            [PreviewDevice([WuCandidate()])], null, new HashSet<string>(), true);
        var executor = new FakeExecutor
        {
            Handler = request => new BatchExecutionResult(
                BatchStatus.Completed,
                request.Approval.Targets
                    .Select(t => new ItemOutcome(t, ItemStatus.Done,
                        "Updated and verified. A reboot is pending to finish.", null, null, true))
                    .ToList(),
                "done"),
        };
        var sheet = SheetFor(preview, executor);

        await sheet.RunAsync();

        Assert.Equal("Update completed", sheet.OutcomeTitle);
        var row = Assert.Single(sheet.ItemResults);
        Assert.Equal("Updated", row.StatusText);
        Assert.Contains("restart is pending", sheet.RestartStateLine);
    }

    [Fact]
    public async Task Sheet_CompletedWithoutReboot_SaysSo()
    {
        var preview = DriverPreviewBuilder.Build(
            [PreviewDevice([WuCandidate()])], null, new HashSet<string>(), true);
        var sheet = SheetFor(preview, new FakeExecutor());

        await sheet.RunAsync();

        Assert.Contains("No restart flagged", sheet.RestartStateLine);
    }

    [Fact]
    public async Task Sheet_RollbackCompleted_SaysRolledBack()
    {
        var preview = DriverPreviewBuilder.BuildRollback(
            [new DriverRollbackRequest(DeviceId, "Intel UHD", null, "31.0.101.2121")],
            _ => [HistoryRow(1, "30.0.100.9805")],
            [StorePkg("oem12.inf", "09/25/2021 30.0.100.9805")],
            true);
        var executor = new FakeExecutor();
        var sheet = new DriverSheetViewModel(preview, RollbackTemplate(), () => DispatcherWith(executor));

        await sheet.RunAsync();

        Assert.Equal("Rollback completed", sheet.OutcomeTitle);
        var row = Assert.Single(sheet.ItemResults);
        Assert.Equal("Rolled back", row.StatusText);
        Assert.Equal(string.Empty, sheet.RollbackHintLine);
        AssertNoFixedWord(sheet.OutcomeTitle, sheet.OutcomeDetail, row.StatusText, row.Detail);
    }

    [Fact]
    public async Task Sheet_ProgressAndViewHistory()
    {
        var preview = DriverPreviewBuilder.Build(
            [PreviewDevice([WuCandidate()])], null, new HashSet<string>(), true);
        var executor = new FakeExecutor();
        bool navigated = false;
        var sheet = new DriverSheetViewModel(preview, UpdateTemplate(), () => DispatcherWith(executor))
        {
            ViewHistory = () => navigated = true,
        };

        Assert.True(sheet.HasViewHistory);
        await sheet.RunAsync();

        Assert.True(sheet.IsDone);
        Assert.False(sheet.IsRunning);
        sheet.ViewHistoryCommand.Execute(null);
        Assert.True(navigated);
    }

    // ---- Drivers page check flow ----

    private DriversViewModel PageWith(FakeOps ops, CapturingHost host, bool withPassport = true)
    {
        string passportPath = Path.Combine(_root, Guid.NewGuid().ToString("N") + ".db");
        var services = new DriverActionServices(
            () => DispatcherWith(new FakeExecutor()),
            host,
            () => ops,
            new FakeSr(),
            () => NewBlocklist(Guid.NewGuid().ToString("N") + ".db"));
        var page = new DriversViewModel(
            withPassport ? () => new PassportDb(passportPath) : null,
            services);
        page.SelectedDevice = SelectedRow();
        return page;
    }

    [Fact]
    public async Task Page_CheckUpdates_FindsCandidate()
    {
        var ops = new FakeOps { SearchFunc = () => [WuCandidate()] };
        var page = PageWith(ops, new CapturingHost());

        await page.CheckUpdatesAsync(CancellationToken.None);

        var candidate = Assert.Single(page.UpdateCandidates);
        Assert.Equal("31.0.101.2121", candidate.Candidate.Version);
        // The candidate is decided either way; whether the sheet
        // may open depends on live elevation (usually unelevated on
        // the build host — the elevated confirm path is covered by
        // the sheet tests above with explicit previews).
        Assert.Equal(ElevationPolicy.IsProcessElevated(), page.CanOpenUpdateSheet);
    }

    [Fact]
    public async Task Page_OpenUpdateSheet_ShowsPreview()
    {
        var ops = new FakeOps { SearchFunc = () => [WuCandidate()] };
        var host = new CapturingHost();
        var page = PageWith(ops, host);

        await page.CheckUpdatesAsync(CancellationToken.None);
        page.OpenUpdateSheet();

        var sheet = Assert.Single(host.Shown);
        var row = Assert.Single(sheet.Included);
        Assert.Equal("30.0.100.9805 → 31.0.101.2121", row.ChangeLine);
    }

    [Fact]
    public async Task Page_CheckUpdates_NoCandidates_ShowsReasonsAndLinks()
    {
        var ops = new FakeOps { SearchFunc = () => [] };
        var page = PageWith(ops, new CapturingHost());

        await page.CheckUpdatesAsync(CancellationToken.None);

        Assert.Empty(page.UpdateCandidates);
        var unsupported = Assert.Single(page.UpdateUnsupported);
        Assert.Contains("no driver", unsupported.Reason);
    }

    [Fact]
    public async Task Page_CheckUpdates_SearchFault_Surfaced()
    {
        var ops = new FakeOps { SearchFunc = () => throw new InvalidOperationException("WU offline") };
        var page = PageWith(ops, new CapturingHost());

        await page.CheckUpdatesAsync(CancellationToken.None);

        Assert.Contains("WU offline", page.UpdateStateLine);
        Assert.False(page.IsChecking);
    }

    [Fact]
    public async Task Page_CheckUpdates_Cancelled()
    {
        var ops = new FakeOps();
        var page = PageWith(ops, new CapturingHost());
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await page.CheckUpdatesAsync(cts.Token);

        Assert.Contains("cancelled", page.UpdateStateLine);
    }

    [Fact]
    public void Page_ActionsUnwired_StaysReadOnly()
    {
        var page = new DriversViewModel();
        page.SelectedDevice = SelectedRow();

        Assert.False(page.ActionsAvailable);
        Assert.False(page.CanCheckUpdates);
        page.OpenUpdateSheet();
        Assert.Contains("stays read-only", page.UpdateStateLine);
    }

    [Fact]
    public void Page_SelectionChange_ClearsCheck()
    {
        var ops = new FakeOps { SearchFunc = () => [WuCandidate()] };
        var page = PageWith(ops, new CapturingHost());
        page.SelectedDevice = null;

        Assert.Empty(page.UpdateCandidates);
        Assert.False(page.CanOpenUpdateSheet);
    }

    [Fact]
    public void Page_OpenLink_RejectsNonHttp()
    {
        var page = PageWith(new FakeOps(), new CapturingHost());
        string before = page.UpdateStateLine;

        page.OpenLink("file:///C:/Windows/System32/evil.exe");
        page.OpenLink(null);
        page.OpenLink("not a url");

        Assert.Equal(before, page.UpdateStateLine);
    }

    [Fact]
    public async Task Page_CheckRollback_FindsTarget()
    {
        var ops = new FakeOps();
        ops.ReadDeviceFunc = _ => new DeviceStatus(true, 0, null, 0, "Intel UHD", "31.0.101.2121",
            "01/10/2022", ["PCI\\VEN_8086&DEV_9BC5"]);
        ops.Store.Add(StorePkg("oem12.inf", "09/25/2021 30.0.100.9805"));

        // Seed history first: the older good version, then live bad.
        string passportPath = Path.Combine(_root, "rb-seed.db");
        using (var passport = new PassportDb(passportPath))
        {
            passport.RecordDeviceStates([
                (DeviceId, "Intel UHD", 0, "Working", "30.0.100.9805"),
                (DeviceId, "Intel UHD", 0, "Working", "31.0.101.2121"),
            ]);
        }

        var services = new DriverActionServices(
            () => DispatcherWith(new FakeExecutor()),
            new CapturingHost(),
            () => ops,
            new FakeSr(),
            () => NewBlocklist("rb-bl.db"));
        var page = new DriversViewModel(() => new PassportDb(passportPath), services);
        page.SelectedDevice = SelectedRow();

        await page.CheckRollbackAsync(CancellationToken.None);

        var candidate = Assert.Single(page.RollbackCandidates);
        Assert.Equal("oem12.inf", candidate.TargetInf);
        Assert.Equal("30.0.100.9805", candidate.PreviousVersion);
    }

    [Fact]
    public async Task Page_CheckRollback_NoHistory_Unsupported()
    {
        var ops = new FakeOps();
        ops.Store.Add(StorePkg("oem12.inf", "09/25/2021 30.0.100.9805"));
        var page = PageWith(ops, new CapturingHost());

        await page.CheckRollbackAsync(CancellationToken.None);

        Assert.Empty(page.RollbackCandidates);
        var unsupported = Assert.Single(page.RollbackUnsupported);
        Assert.Contains("No earlier driver version is on record", unsupported.Reason);
    }

    [Fact]
    public async Task Page_CheckRollback_NoPassport_Stated()
    {
        var page = PageWith(new FakeOps(), new CapturingHost(), withPassport: false);

        await page.CheckRollbackAsync(CancellationToken.None);

        Assert.Contains("history is unavailable", page.RollbackStateLine);
    }
}
