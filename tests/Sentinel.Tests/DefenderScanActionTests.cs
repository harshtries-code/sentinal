using Sentinel.App.ViewModels;
using Sentinel.Engine.Actions;
using Sentinel.Engine.Policy;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.Tests;

// T50: defender_scan as an audited app action. Launches run through
// a scripted IDefenderProcess — no Defender process starts on the
// host here (benign/EICAR plumbing is VM-battery-only). States:
// launched-running, completed-clean, completed-threats, refused,
// failed, cancelled. Remediation is always Defender-owned.
public sealed class DefenderScanActionTests : IDisposable
{
    private readonly string _root;

    public DefenderScanActionTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "sentinel-t50-" + Guid.NewGuid().ToString("N"));
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

    private sealed class FakeProcess : IDefenderProcess
    {
        public Func<string, string, DefenderLaunch> Handler { get; set; } =
            (_, _) => new DefenderLaunch(true, 1234, false, null, "fake running");

        public List<(string Exe, string Args)> Calls { get; } = [];

        public DefenderLaunch Launch(string exe, string args, int settleMs, CancellationToken ct)
        {
            Calls.Add((exe, args));
            return Handler(exe, args);
        }
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
            module == "Threats" ? PermissionLevel.L2 : PermissionLevel.L0;
    }

    private sealed class FakeExecutor : IActionExecutor
    {
        public List<ActionApproval> Seen { get; } = [];

        public Func<BatchExecutionRequest, BatchExecutionResult>? Handler { get; set; }

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

    private sealed class CapturingHost : IDefenderScanSheetHost
    {
        public List<DefenderScanSheetViewModel> Shown { get; } = [];

        public void Show(DefenderScanSheetViewModel sheet) => Shown.Add(sheet);
    }

    private static ActionTemplate Template() =>
        ActionRegistry.All.First(t => t.Id == "defender_scan");

    private static ActionTarget ScanTarget(DefenderScanAux aux, string expected = "quick scan") =>
        new("scan:0", expected, "scan", RiskTier.Review, 0, 0, null, aux.ToJson());

    private static ActionApproval Approval(params ActionTarget[] targets) =>
        new("defender_scan", targets, [], [], 1, DateTimeOffset.UtcNow,
            ActionActors.User, Guid.NewGuid().ToString("N"));

    private static DefenderDetectionRecord Detection(string name) =>
        new(name, 1, "High", "Virus", @"C:\x", DateTime.UtcNow, "Quarantined", false);

    private DefenderScanExecutor ExecutorFor(
        FakeProcess process,
        CapturingAudit audit,
        Func<IReadOnlyList<DefenderDetectionRecord>>? detections = null,
        bool elevated = true,
        int? productType = 1,
        string? exePath = null)
    {
        // The executor re-checks tool existence: materialize a fake.
        string fakeExe = exePath ?? Path.Combine(_root, "MpCmdRun.exe");
        if (exePath is null)
        {
            File.WriteAllBytes(fakeExe, [0x4D, 0x5A]);
        }

        return new DefenderScanExecutor(process,
            detections ?? (() => []),
            audit,
            exeLocator: () => fakeExe,
            elevationProbe: () => elevated,
            productTypeReader: () => productType);
    }

    // ---- exit semantics ----

    [Fact]
    public void InterpretExit_Zero_Clean()
    {
        var (completed, threats, detail) = DefenderScan.InterpretExit(0);
        Assert.True(completed);
        Assert.False(threats);
        Assert.Contains("no threats", detail);
    }

    [Fact]
    public void InterpretExit_Two_ThreatsDefenderOwned()
    {
        var (completed, threats, detail) = DefenderScan.InterpretExit(2);
        Assert.True(completed);
        Assert.True(threats);
        Assert.Contains("Defender-owned", detail);
    }

    [Theory]
    [InlineData(5, "exit 5")]
    [InlineData(-2147024891, "HRESULT 0x80070005")]
    public void InterpretExit_Other_Failed(int code, string word)
    {
        var (completed, threats, detail) = DefenderScan.InterpretExit(code);
        Assert.False(completed);
        Assert.False(threats);
        Assert.Contains(word, detail);
    }

    // ---- offline gates ----

    [Fact]
    public void OfflineCommand_IsFixed()
    {
        var (exe, args) = DefenderScan.OfflineCommand();
        Assert.Equal("powershell.exe", exe);
        Assert.DoesNotContain("\"", args);
        Assert.Contains("Start-MpWDOScan", args);
    }

    [Theory]
    [InlineData(1, true)]
    [InlineData(2, false)]
    [InlineData(3, false)]
    [InlineData(null, false)]
    public void OfflineSupported_ProductType(int? productType, bool expected)
    {
        if (Environment.OSVersion.Platform != PlatformID.Win32NT && expected)
        {
            return; // Positive leg needs Windows.
        }

        Assert.Equal(expected, DefenderScan.OfflineSupported(() => productType));
    }

    [Fact]
    public void OfflineSupported_ReaderThrows_False()
    {
        Assert.False(DefenderScan.OfflineSupported(() => throw new InvalidOperationException()));
    }

    [Fact]
    public void Plan_Offline_SupportedReady()
    {
        if (Environment.OSVersion.Platform != PlatformID.Win32NT)
        {
            return;
        }

        var plan = DefenderScan.Plan(
            new DefenderScanRequest(DefenderScanKind.Offline, null), productTypeReader: () => 1);
        Assert.True(plan.Ready);
        Assert.Contains("Start-MpWDOScan", plan.CommandLine);
        Assert.Contains("restart acknowledgement", plan.Detail);
    }

    [Fact]
    public void Plan_Offline_UnsupportedRefused()
    {
        var plan = DefenderScan.Plan(
            new DefenderScanRequest(DefenderScanKind.Offline, null), productTypeReader: () => 3);
        Assert.False(plan.Ready);
        Assert.Contains("not supported", plan.Detail);
    }

    // ---- executor: outcomes ----

    [Fact]
    public async Task Scan_CompletedClean_DoneWithImport()
    {
        var process = new FakeProcess
        {
            Handler = (_, _) => new DefenderLaunch(true, 111, true, 0, "exited 0"),
        };
        var audit = new CapturingAudit();
        var executor = ExecutorFor(process, audit,
            detections: () => [Detection("Evil.Test"), Detection("Older.Test")]);

        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(ScanTarget(new DefenderScanAux("quick", null, false))),
            Template(), null, null), CancellationToken.None);

        Assert.Equal(BatchStatus.Completed, result.Status);
        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Done, item.Status);
        Assert.Contains("no threats reported", item.Detail);
        Assert.Contains("2 detection(s)", item.Detail);
        Assert.Contains("Evil.Test", item.Detail);
        Assert.False(item.UndoAvailable);
        var draft = Assert.Single(audit.Drafts);
        Assert.Equal("none-defender-owned", draft.BackupRef);
        Assert.Equal("None", draft.UndoState);
        var (exe, args) = Assert.Single(process.Calls);
        Assert.Contains("-ScanType 1", args);
    }

    [Fact]
    public async Task Scan_ThreatsReported_DoneDefenderOwned()
    {
        var process = new FakeProcess
        {
            Handler = (_, _) => new DefenderLaunch(true, 222, true, 2, "exited 2"),
        };
        var executor = ExecutorFor(process, new CapturingAudit());

        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(ScanTarget(new DefenderScanAux("full", null, false))),
            Template(), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Done, item.Status);
        Assert.Contains("Defender-owned", item.Detail);
        Assert.Contains("Sentinel changed nothing", item.Detail);
    }

    [Fact]
    public async Task Scan_Hresult_Failed()
    {
        var process = new FakeProcess
        {
            Handler = (_, _) => new DefenderLaunch(true, 333, true, -2147024891, "hresult"),
        };
        var executor = ExecutorFor(process, new CapturingAudit());

        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(ScanTarget(new DefenderScanAux("quick", null, false))),
            Template(), null, null), CancellationToken.None);

        Assert.Equal(BatchStatus.Failed, result.Status);
        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Failed, item.Status);
        Assert.Contains("0x80070005", item.Detail);
    }

    [Fact]
    public async Task Scan_StillRunning_LaunchedState()
    {
        var process = new FakeProcess
        {
            Handler = (exe, args) =>
            {
                Assert.Contains("-ScanType 2", args);
                return new DefenderLaunch(true, 4444, false, null, "running");
            },
        };
        var executor = ExecutorFor(process, new CapturingAudit());

        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(ScanTarget(new DefenderScanAux("full", null, false))),
            Template(), null, null), CancellationToken.None);

        Assert.Equal(BatchStatus.Completed, result.Status);
        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Done, item.Status);
        Assert.Contains("4444", item.Detail);
        Assert.Contains("still running", item.Detail);
        Assert.Contains("Windows Security", item.Detail);
    }

    [Fact]
    public async Task Scan_LaunchRefused_Failed()
    {
        var process = new FakeProcess
        {
            Handler = (_, _) => new DefenderLaunch(false, null, true, null, "access denied"),
        };
        var executor = ExecutorFor(process, new CapturingAudit());

        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(ScanTarget(new DefenderScanAux("quick", null, false))),
            Template(), null, null), CancellationToken.None);

        Assert.Equal(BatchStatus.Failed, result.Status);
        var item = Assert.Single(result.Items);
        Assert.Equal("Launch/Refused", item.RevalidationVerdict);
    }

    [Fact]
    public async Task Scan_ImportThrows_OutcomeStandsWithNote()
    {
        var process = new FakeProcess
        {
            Handler = (_, _) => new DefenderLaunch(true, 555, true, 0, "exited 0"),
        };
        var executor = ExecutorFor(process, new CapturingAudit(),
            detections: () => throw new InvalidOperationException("wmi down"));

        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(ScanTarget(new DefenderScanAux("quick", null, false))),
            Template(), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Done, item.Status);
        Assert.Contains("import failed", item.Detail);
    }

    // ---- executor: refusals ----

    [Fact]
    public async Task Scan_WrongTemplate_Failed()
    {
        var executor = ExecutorFor(new FakeProcess(), new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(ScanTarget(new DefenderScanAux("quick", null, false))),
            ActionRegistry.All.First(t => t.Id == "clean_items_to_vault"), null, null),
            CancellationToken.None);
        Assert.Equal(BatchStatus.Failed, result.Status);
    }

    [Fact]
    public async Task Scan_WrongKind_Refused()
    {
        var process = new FakeProcess();
        var executor = ExecutorFor(process, new CapturingAudit());
        var target = ScanTarget(new DefenderScanAux("quick", null, false)) with { Kind = "file" };
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(target), Template(), null, null), CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, result.Status);
        Assert.Empty(process.Calls);
    }

    [Theory]
    [InlineData("{broken")]
    [InlineData(null)]
    public async Task Scan_MalformedAux_Refused(string? auxJson)
    {
        var process = new FakeProcess();
        var executor = ExecutorFor(process, new CapturingAudit());
        var target = new ActionTarget("scan:0", "quick scan", "scan",
            RiskTier.Review, 0, 0, null, auxJson);
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(target), Template(), null, null), CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, result.Status);
        Assert.Empty(process.Calls);
    }

    [Fact]
    public async Task Scan_UnknownKind_Refused()
    {
        var process = new FakeProcess();
        var executor = ExecutorFor(process, new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(ScanTarget(new DefenderScanAux("hyper", null, false))),
            Template(), null, null), CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, result.Status);
        Assert.Empty(process.Calls);
    }

    [Fact]
    public async Task Scan_Unelevated_RefusedRelaunch()
    {
        var process = new FakeProcess();
        var executor = ExecutorFor(process, new CapturingAudit(), elevated: false);
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(ScanTarget(new DefenderScanAux("quick", null, false))),
            Template(), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Refused, item.Status);
        Assert.Contains("relaunch Sentinel as administrator", item.Detail);
        Assert.Empty(process.Calls);
    }

    [Fact]
    public async Task Scan_FolderVanished_Refused()
    {
        var process = new FakeProcess();
        var executor = ExecutorFor(process, new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(ScanTarget(new DefenderScanAux("folder",
                Path.Combine(_root, "nope-" + Guid.NewGuid().ToString("N")), false))),
            Template(), null, null), CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, result.Status);
        Assert.Empty(process.Calls);
    }

    [Fact]
    public async Task Scan_Folder_QuotesTarget()
    {
        string dir = Path.Combine(_root, "with space");
        Directory.CreateDirectory(dir);
        (string Exe, string Args) seen = default;
        var process = new FakeProcess
        {
            Handler = (exe, args) =>
            {
                seen = (exe, args);
                return new DefenderLaunch(true, 1, true, 0, "ok");
            },
        };
        var executor = ExecutorFor(process, new CapturingAudit());

        await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(ScanTarget(new DefenderScanAux("folder", dir, false), dir)),
            Template(), null, null), CancellationToken.None);

        Assert.Contains("-ScanType 3", seen.Args);
        Assert.Contains($"\"{Path.GetFullPath(dir)}\"", seen.Args);
    }

    [Fact]
    public async Task Scan_ToolMissing_Refused()
    {
        var process = new FakeProcess();
        var executor = new DefenderScanExecutor(process, () => [], new CapturingAudit(),
            exeLocator: () => null, elevationProbe: () => true,
            productTypeReader: () => 1);
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(ScanTarget(new DefenderScanAux("quick", null, false))),
            Template(), null, null), CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, result.Status);
        Assert.Empty(process.Calls);
    }

    [Fact]
    public async Task Scan_OfflineUnsupported_Refused()
    {
        var process = new FakeProcess();
        var executor = ExecutorFor(process, new CapturingAudit(), productType: 3);
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(ScanTarget(new DefenderScanAux("offline", null, true))),
            Template(), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Refused, item.Status);
        Assert.Equal("Offline/Unsupported", item.RevalidationVerdict);
        Assert.Empty(process.Calls);
    }

    [Fact]
    public async Task Scan_OfflineNoAck_Refused()
    {
        var process = new FakeProcess();
        var executor = ExecutorFor(process, new CapturingAudit(), productType: 1);
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(ScanTarget(new DefenderScanAux("offline", null, false))),
            Template(), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal("Offline/NoRestartAck", item.RevalidationVerdict);
        Assert.Empty(process.Calls);
    }

    [Fact]
    public async Task Scan_OfflineAck_LaunchesFixedCommand()
    {
        (string Exe, string Args) seen = default;
        var process = new FakeProcess
        {
            Handler = (exe, args) =>
            {
                seen = (exe, args);
                return new DefenderLaunch(true, 777, false, null, "rebooting");
            },
        };
        var executor = ExecutorFor(process, new CapturingAudit(), productType: 1);
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(ScanTarget(new DefenderScanAux("offline", null, true))),
            Template(), null, null), CancellationToken.None);

        Assert.Equal(("powershell.exe", "-NoProfile -NonInteractive -Command Start-MpWDOScan"), seen);
        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Done, item.Status);
        Assert.Contains("restart", item.Detail);
    }

    [Fact]
    public async Task Scan_Cancelled_NeverLaunches()
    {
        var process = new FakeProcess();
        var executor = ExecutorFor(process, new CapturingAudit());
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(ScanTarget(new DefenderScanAux("quick", null, false))),
            Template(), null, null), cts.Token);

        Assert.Equal(BatchStatus.Cancelled, result.Status);
        Assert.Empty(process.Calls);
    }

    [Fact]
    public async Task Scan_ProcessThrows_Failed()
    {
        var process = new FakeProcess
        {
            Handler = (_, _) => throw new InvalidOperationException("seam exploded"),
        };
        var executor = ExecutorFor(process, new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(ScanTarget(new DefenderScanAux("quick", null, false))),
            Template(), null, null), CancellationToken.None);

        // The backstop catches seam throws: Failed, never a crash.
        Assert.Equal(BatchStatus.Failed, result.Status);
    }

    // ---- sheet ----

    private static ActionDispatcher DispatcherWith(FakeExecutor executor)
    {
        var dispatcher = new ActionDispatcher(new CapturingAudit(), new FixedLevels());
        Assert.True(dispatcher.RegisterExecutor("defender_scan", executor));
        return dispatcher;
    }

    [Fact]
    public void Sheet_Lines_NameCommandAndWarning()
    {
        var request = new DefenderScanRequest(DefenderScanKind.Full, null);
        var plan = DefenderScan.Plan(request,
            exeOverrideDir: Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        var sheet = new DefenderScanSheetViewModel(request, plan, Template(), () => null!);

        Assert.Contains("-Scan -ScanType 2", sheet.CommandLine);
        Assert.Contains("quarantine", sheet.RemediationLine);
        Assert.Contains("removes nothing itself", sheet.RemediationLine);
        Assert.False(sheet.NeedsRestartAck);
    }

    [Fact]
    public void Sheet_Offline_RequiresRestartAck()
    {
        var request = new DefenderScanRequest(DefenderScanKind.Offline, null);
        var plan = new DefenderScanPlan("offline scan (restarts this PC)",
            "powershell.exe -NoProfile -NonInteractive -Command Start-MpWDOScan", true, "planned");
        var sheet = new DefenderScanSheetViewModel(request, plan, Template(), () => null!);

        Assert.True(sheet.NeedsRestartAck);
        Assert.False(sheet.ConfirmCommand.CanExecute(null));
        sheet.RestartAcknowledged = true;
        Assert.True(sheet.ConfirmCommand.CanExecute(null));
    }

    [Fact]
    public void Sheet_RefusedPreview_DisablesConfirm()
    {
        var request = new DefenderScanRequest(DefenderScanKind.Quick, null);
        var plan = new DefenderScanPlan("quick scan", "MpCmdRun.exe", false, "tool missing");
        var sheet = new DefenderScanSheetViewModel(request, plan, Template(), () => null!);

        Assert.True(sheet.IsRefusedPreview);
        Assert.False(sheet.ConfirmCommand.CanExecute(null));
    }

    [Fact]
    public async Task Sheet_Run_BuildsScanApproval()
    {
        string dir = Path.Combine(_root, "target");
        Directory.CreateDirectory(dir);
        var request = new DefenderScanRequest(DefenderScanKind.Folder, dir);
        var plan = new DefenderScanPlan("folder scan", "MpCmdRun.exe -Scan -ScanType 3", true, "planned");
        var executor = new FakeExecutor();
        var sheet = new DefenderScanSheetViewModel(request, plan, Template(), () => DispatcherWith(executor));

        await sheet.RunAsync();

        Assert.True(sheet.IsDone);
        var approval = Assert.Single(executor.Seen);
        Assert.Equal("defender_scan", approval.TemplateId);
        var target = Assert.Single(approval.Targets);
        Assert.Equal("scan", target.Kind);
        Assert.Equal(RiskTier.Review, target.ApprovedTier);
        var aux = DefenderScanAux.Parse(target.AuxJson);
        Assert.NotNull(aux);
        Assert.Equal("folder", aux.Kind);
        Assert.Equal(dir, aux.Path);
        Assert.False(aux.RestartAcknowledged);
    }

    [Fact]
    public async Task Sheet_OfflineRun_CarriesAck()
    {
        var request = new DefenderScanRequest(DefenderScanKind.Offline, null);
        var plan = new DefenderScanPlan("offline scan", "powershell.exe ...", true, "planned");
        var executor = new FakeExecutor();
        var sheet = new DefenderScanSheetViewModel(request, plan, Template(), () => DispatcherWith(executor))
        {
            RestartAcknowledged = true,
        };

        await sheet.RunAsync();

        var aux = DefenderScanAux.Parse(Assert.Single(Assert.Single(executor.Seen).Targets).AuxJson);
        Assert.NotNull(aux);
        Assert.Equal("offline", aux.Kind);
        Assert.True(aux.RestartAcknowledged);
    }

    [Fact]
    public async Task Sheet_Outcomes_Titled()
    {
        var request = new DefenderScanRequest(DefenderScanKind.Quick, null);
        var plan = new DefenderScanPlan("quick scan", "MpCmdRun.exe -Scan -ScanType 1", true, "planned");
        var executor = new FakeExecutor
        {
            Handler = _ => new BatchExecutionResult(BatchStatus.Completed,
                [new ItemOutcome(
                    new ActionTarget("scan:0", "quick scan", "scan", RiskTier.Review, 0, 0, null, "{}"),
                    ItemStatus.Done, "Defender completed the scan — no threats reported.",
                    null, null, false)],
                "done"),
        };
        var sheet = new DefenderScanSheetViewModel(request, plan, Template(), () => DispatcherWith(executor));

        await sheet.RunAsync();

        Assert.Equal("Scan requested", sheet.OutcomeTitle);
        Assert.Contains("no threats reported", sheet.OutcomeDetail);
    }

    [Fact]
    public async Task Sheet_RefusedOutcome_Titled()
    {
        var request = new DefenderScanRequest(DefenderScanKind.Quick, null);
        var plan = new DefenderScanPlan("quick scan", "MpCmdRun.exe -Scan -ScanType 1", true, "planned");
        var executor = new FakeExecutor
        {
            Handler = request2 => new BatchExecutionResult(BatchStatus.Refused,
                request2.Approval.Targets
                    .Select(t => new ItemOutcome(t, ItemStatus.Refused, "elevation", null, null, false))
                    .ToList(),
                "refused"),
        };
        var sheet = new DefenderScanSheetViewModel(request, plan, Template(), () => DispatcherWith(executor));

        await sheet.RunAsync();

        Assert.Equal("No scan started", sheet.OutcomeTitle);
    }

    // ---- page ----

    [Fact]
    public void Page_BeginScan_InvalidTarget_StaysNote()
    {
        var model = new ThreatsViewModel();
        model.BeginScan(new DefenderScanRequest(DefenderScanKind.Folder,
            Path.Combine(_root, "nope-" + Guid.NewGuid().ToString("N"))));

        Assert.Contains("Not found", model.ScanNote);
    }

    [Fact]
    public void Page_BeginScan_NoActions_StaysNote()
    {
        if (DefenderScan.ResolveExe() is null)
        {
            return; // No tool: the not-ready path is covered above.
        }

        var model = new ThreatsViewModel();
        model.BeginScan(new DefenderScanRequest(DefenderScanKind.Quick, null));

        Assert.Contains("unavailable in this build", model.ScanNote);
    }

    [Fact]
    public void Page_BeginScan_Ready_OpensSheet()
    {
        if (DefenderScan.ResolveExe() is null)
        {
            return;
        }

        var host = new CapturingHost();
        var executor = new FakeExecutor();
        var model = new ThreatsViewModel(new ThreatActionServices(
            () => DispatcherWith(executor), host));
        Assert.True(model.ScanActionsAvailable);

        model.BeginScan(new DefenderScanRequest(DefenderScanKind.Quick, null));

        var sheet = Assert.Single(host.Shown);
        Assert.Contains("-ScanType 1", sheet.CommandLine);
    }

    [Fact]
    public async Task Dispatch_ActiveScanWithoutExecutor_RefusedNotImplemented()
    {
        var dispatcher = new ActionDispatcher(new CapturingAudit(), new FixedLevels());
        var outcome = await dispatcher.DispatchAsync(
            Approval(ScanTarget(new DefenderScanAux("quick", null, false))),
            null, CancellationToken.None);
        Assert.Equal(BatchStatus.Refused, outcome.Status);
        Assert.Equal(RefusalCode.TemplateNotImplemented, outcome.Refusal);
    }
}
