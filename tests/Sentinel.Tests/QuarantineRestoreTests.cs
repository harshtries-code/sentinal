using Sentinel.App.ViewModels;
using Sentinel.Engine.Actions;
using Sentinel.Engine.Policy;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.Tests;

// T52: current-quarantine explanation + typed restore. Launches
// run through a scripted IDefenderProcess â€” no MpCmdRun starts
// on the host here (the live list-format confirmation and the
// restore round-trip are VM-battery-only). Re-quarantine stays
// Proposed: no supported verb exists (DEC-REQUARANTINE).
public sealed class QuarantineRestoreTests : IDisposable
{
    private readonly string _root;

    public QuarantineRestoreTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "sentinel-t52-" + Guid.NewGuid().ToString("N"));
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
            (_, _) => new DefenderLaunch(true, 1234, true, 0, "fake exited 0");

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

    private sealed class CapturingQuarantineHost : IQuarantineSheetHost
    {
        public List<QuarantineSheetViewModel> Shown { get; } = [];

        public void Show(QuarantineSheetViewModel sheet) => Shown.Add(sheet);
    }

    private sealed class NoopScanHost : IDefenderScanSheetHost
    {
        public void Show(DefenderScanSheetViewModel sheet)
        {
        }
    }

    private static ActionTemplate Template() =>
        ActionRegistry.All.First(t => t.Id == "quarantine_restore");

    private static ActionTarget RestoreTarget(string name) =>
        new("quarantine:0", name, "quarantine", RiskTier.Review, 0, 0, null,
            new QuarantineRestoreAux(name).ToJson());

    private static ActionApproval Approval(params ActionTarget[] targets) =>
        new("quarantine_restore", targets, [], [], 1, DateTimeOffset.UtcNow,
            ActionActors.User, Guid.NewGuid().ToString("N"));

    private static BatchExecutionRequest Request(params ActionTarget[] targets) =>
        new(Approval(targets), Template(), null, null);

    private static QuarantineRecord Listed(string name) =>
        new(name, name, @"C:\x", "today", $"Name: {name}");

    private QuarantineRestoreExecutor ExecutorFor(
        FakeProcess process,
        CapturingAudit audit,
        Func<IReadOnlyList<QuarantineRecord>>? reader = null,
        bool elevated = true,
        string? exePath = null)
    {
        string fakeExe = exePath ?? Path.Combine(_root, "MpCmdRun.exe");
        if (exePath is null)
        {
            File.WriteAllBytes(fakeExe, [0x4D, 0x5A]);
        }

        return new QuarantineRestoreExecutor(process,
            reader ?? (() => []),
            audit,
            exeLocator: () => fakeExe,
            elevationProbe: () => elevated);
    }

    private static ActionDispatcher DispatcherWith(FakeExecutor executor)
    {
        var dispatcher = new ActionDispatcher(new CapturingAudit(), new FixedLevels());
        Assert.True(dispatcher.RegisterExecutor("quarantine_restore", executor));
        return dispatcher;
    }

    // ---- list parsing ----

    [Fact]
    public void ParseBlock_Maps_Name_Threat_Path_Detected()
    {
        var record = QuarantineCollector.ParseBlock(
        [
            "Name: Evil:Win32/Test",
            "Threat: Trojan:Script/Test",
            "File Path: C:\\bad\\x.exe",
            "Detection Time: 2026-01-02 03:04:05",
        ]);

        Assert.NotNull(record);
        Assert.Equal("Evil:Win32/Test", record.Name);
        Assert.Equal("Trojan:Script/Test", record.Threat);
        Assert.Equal(@"C:\bad\x.exe", record.Path);
        Assert.Equal("2026-01-02 03:04:05", record.Detected);
        Assert.Contains("Name: Evil:Win32/Test", record.Raw);
    }

    [Fact]
    public void ParseBlock_Without_Name_Returns_Null()
    {
        Assert.Null(QuarantineCollector.ParseBlock(["CmdTool: some header line"]));
        Assert.Null(QuarantineCollector.ParseBlock(["no colon here"]));
    }

    [Fact]
    public void ParseList_Counts_Unparsed_Blocks()
    {
        var (records, unparsed) = QuarantineCollector.ParseList(
            "CmdTool: header\n\nName: A\nThreat: T\n\njunk without name: x",
            QuarantineCollector.MaxEntries);

        Assert.Equal(2, unparsed);
        Assert.Single(records);
    }

    [Fact]
    public void Collect_Fixture_Output_Succeeds()
    {
        var result = QuarantineCollector.Collect(
            () => (0, "Name: A\nThreat: T\n\nName: B\n"));

        Assert.Equal(CollectionStatus.Success, result.Status);
        Assert.Equal(2, result.Records.Count);
    }

    [Fact]
    public void Collect_Empty_List_Succeeds_Empty()
    {
        var result = QuarantineCollector.Collect(() => (0, "\n"));

        Assert.Equal(CollectionStatus.Success, result.Status);
        Assert.Empty(result.Records);
    }

    [Fact]
    public void Collect_AccessDenied_Fails_ElevationRequired()
    {
        // Observed on host: even listing needs administrator.
        var result = QuarantineCollector.Collect(
            () => (2, "You need administrator privilege to execute this command.\n" +
                "CmdTool: Failed with hr = 0x80070005."));

        Assert.Equal(CollectionStatus.Failed, result.Status);
        Assert.Empty(result.Records);
        Assert.Contains(result.Gaps, g => g.Reason == "ElevationRequired");
    }

    [Fact]
    public void Collect_NonZero_Exit_Fails_ListFailed()
    {
        var result = QuarantineCollector.Collect(() => (5, "boom"));

        Assert.Equal(CollectionStatus.Failed, result.Status);
        Assert.Contains(result.Gaps, g => g.Reason == "ListFailed");
    }

    [Fact]
    public void Collect_Reader_Throws_Fails()
    {
        var result = QuarantineCollector.Collect(
            () => throw new InvalidOperationException("no tool"));

        Assert.Equal(CollectionStatus.Failed, result.Status);
    }

    [Fact]
    public void Collect_Missing_Tool_Fails_ToolMissing()
    {
        var result = QuarantineCollector.Collect(
            listReader: null, exeLocator: () => null);

        Assert.Equal(CollectionStatus.Failed, result.Status);
        Assert.Contains(result.Gaps, g => g.Reason == "ToolMissing");
    }

    // ---- exit semantics ----

    [Fact]
    public void InterpretRestoreExit_Zero_Restored()
    {
        var (restored, detail) = QuarantineRestoreExecutor.InterpretRestoreExit(0);
        Assert.True(restored);
        Assert.Contains("restored", detail);
    }

    [Theory]
    [InlineData(2, "exit 2")]
    [InlineData(5, "exit 5")]
    [InlineData(-2147024891, "HRESULT 0x80070005")]
    public void InterpretRestoreExit_Other_Failed(int code, string word)
    {
        var (restored, detail) = QuarantineRestoreExecutor.InterpretRestoreExit(code);
        Assert.False(restored);
        Assert.Contains(word, detail);
    }

    // ---- executor ----

    [Fact]
    public async Task Restore_RoundTrip_Verifies_Name_Gone()
    {
        var process = new FakeProcess();
        var audit = new CapturingAudit();
        var lists = new Queue<IReadOnlyList<QuarantineRecord>>([
            [Listed("Evil")],
            [],
        ]);
        var executor = ExecutorFor(process, audit, () => lists.Dequeue());

        var result = await executor.ExecuteAsync(
            Request(RestoreTarget("Evil")),
            CancellationToken.None);

        Assert.Equal(BatchStatus.Completed, result.Status);
        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Done, item.Status);
        Assert.Contains("no longer in quarantine", item.Detail);
        var call = Assert.Single(process.Calls);
        Assert.Equal("-Restore -Name \"Evil\"", call.Args);
        Assert.Contains(audit.Drafts, d => d.BackupRef == "defender-owned-restore");
    }

    [Fact]
    public async Task Restore_WrongTemplate_Fails()
    {
        var executor = ExecutorFor(new FakeProcess(), new CapturingAudit());
        var other = ActionRegistry.All.First(t => t.Id == "defender_scan");

        var result = await executor.ExecuteAsync(
            new BatchExecutionRequest(Approval(RestoreTarget("Evil")), other, null, null),
            CancellationToken.None);

        Assert.Equal(BatchStatus.Failed, result.Status);
        Assert.Contains("Nothing was done", result.Note);
    }

    [Fact]
    public async Task Restore_WrongKind_Refused()
    {
        var executor = ExecutorFor(new FakeProcess(), new CapturingAudit());
        var target = new ActionTarget("x:0", "Evil", "scan", RiskTier.Review, 0, 0, null,
            new QuarantineRestoreAux("Evil").ToJson());

        var result = await executor.ExecuteAsync(
            Request(target),
            CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, result.Status);
        Assert.Equal("Kind/Wrong", Assert.Single(result.Items).RevalidationVerdict);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("not json")]
    [InlineData("  ")]
    public async Task Restore_MalformedAux_Refused(string? auxJson)
    {
        var executor = ExecutorFor(new FakeProcess(), new CapturingAudit());
        var target = new ActionTarget("quarantine:0", "?", "quarantine",
            RiskTier.Review, 0, 0, null, auxJson);

        var result = await executor.ExecuteAsync(
            Request(target),
            CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, result.Status);
        Assert.Equal("Aux/Malformed", Assert.Single(result.Items).RevalidationVerdict);
    }

    [Fact]
    public async Task Restore_Unelevated_Refused()
    {
        var process = new FakeProcess();
        var executor = ExecutorFor(process, new CapturingAudit(), elevated: false);

        var result = await executor.ExecuteAsync(
            Request(RestoreTarget("Evil")),
            CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, result.Status);
        Assert.Equal("Elevation/Required", Assert.Single(result.Items).RevalidationVerdict);
        Assert.Empty(process.Calls);
    }

    [Fact]
    public async Task Restore_ToolMissing_Refused_Stays_Missing()
    {
        var process = new FakeProcess();
        var executor = ExecutorFor(process, new CapturingAudit(),
            exePath: Path.Combine(_root, "nope", "MpCmdRun.exe"));

        var result = await executor.ExecuteAsync(
            Request(RestoreTarget("Evil")),
            CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, result.Status);
        Assert.Equal("Tool/Missing", Assert.Single(result.Items).RevalidationVerdict);
        Assert.Empty(process.Calls);
    }

    [Fact]
    public async Task Restore_NameNotListed_Refused()
    {
        var process = new FakeProcess();
        var executor = ExecutorFor(process, new CapturingAudit(),
            reader: () => [Listed("SomethingElse")]);

        var result = await executor.ExecuteAsync(
            Request(RestoreTarget("Evil")),
            CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, result.Status);
        var item = Assert.Single(result.Items);
        Assert.Equal("Target/Changed", item.RevalidationVerdict);
        Assert.Contains("not in current quarantine", item.Detail);
        Assert.Empty(process.Calls);
    }

    [Fact]
    public async Task Restore_UnreadableList_Refused()
    {
        var executor = ExecutorFor(new FakeProcess(), new CapturingAudit(),
            reader: () => throw new UnauthorizedAccessException("denied"));

        var result = await executor.ExecuteAsync(
            Request(RestoreTarget("Evil")),
            CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, result.Status);
        Assert.Equal("Target/Unreadable", Assert.Single(result.Items).RevalidationVerdict);
    }

    [Fact]
    public async Task Restore_LaunchThrows_Failed()
    {
        var process = new FakeProcess
        {
            Handler = (_, _) => throw new InvalidOperationException("no start"),
        };
        var executor = ExecutorFor(process, new CapturingAudit(),
            reader: () => [Listed("Evil")]);

        var result = await executor.ExecuteAsync(
            Request(RestoreTarget("Evil")),
            CancellationToken.None);

        Assert.Equal(BatchStatus.Failed, result.Status);
        Assert.Equal("Launch/Failed", Assert.Single(result.Items).RevalidationVerdict);
    }

    [Fact]
    public async Task Restore_NotStarted_Failed()
    {
        var process = new FakeProcess
        {
            Handler = (_, _) => new DefenderLaunch(false, null, true, null, "denied"),
        };
        var executor = ExecutorFor(process, new CapturingAudit(),
            reader: () => [Listed("Evil")]);

        var result = await executor.ExecuteAsync(
            Request(RestoreTarget("Evil")),
            CancellationToken.None);

        Assert.Equal(BatchStatus.Failed, result.Status);
        Assert.Equal("Launch/Refused", Assert.Single(result.Items).RevalidationVerdict);
    }

    [Fact]
    public async Task Restore_StillRunning_VerifyOnRefresh()
    {
        var process = new FakeProcess
        {
            Handler = (_, _) => new DefenderLaunch(true, 77, false, null, "running"),
        };
        var executor = ExecutorFor(process, new CapturingAudit(),
            reader: () => [Listed("Evil")]);

        var result = await executor.ExecuteAsync(
            Request(RestoreTarget("Evil")),
            CancellationToken.None);

        Assert.Equal(BatchStatus.Completed, result.Status);
        Assert.Contains("verify on the next Threats refresh",
            Assert.Single(result.Items).Detail);
    }

    [Fact]
    public async Task Restore_BadExit_Failed()
    {
        var process = new FakeProcess
        {
            Handler = (_, _) => new DefenderLaunch(true, 77, true, 5, "exited 5"),
        };
        var executor = ExecutorFor(process, new CapturingAudit(),
            reader: () => [Listed("Evil")]);

        var result = await executor.ExecuteAsync(
            Request(RestoreTarget("Evil")),
            CancellationToken.None);

        Assert.Equal(BatchStatus.Failed, result.Status);
        Assert.Equal("Restore/Failed", Assert.Single(result.Items).RevalidationVerdict);
    }

    [Fact]
    public async Task Restore_StillListed_AfterCleanExit_Failed()
    {
        var executor = ExecutorFor(new FakeProcess(), new CapturingAudit(),
            reader: () => [Listed("Evil")]);

        var result = await executor.ExecuteAsync(
            Request(RestoreTarget("Evil")),
            CancellationToken.None);

        Assert.Equal(BatchStatus.Failed, result.Status);
        var item = Assert.Single(result.Items);
        Assert.Equal("Restore/Unverified", item.RevalidationVerdict);
        Assert.Contains("still listed", item.Detail);
    }

    [Fact]
    public async Task Restore_VerifyThrows_Failed()
    {
        var calls = 0;
        IReadOnlyList<QuarantineRecord> Reader()
        {
            calls++;
            return calls == 1
                ? [Listed("Evil")]
                : throw new UnauthorizedAccessException("denied");
        }

        var executor = ExecutorFor(new FakeProcess(), new CapturingAudit(), Reader);

        var result = await executor.ExecuteAsync(
            Request(RestoreTarget("Evil")),
            CancellationToken.None);

        Assert.Equal(BatchStatus.Failed, result.Status);
        Assert.Equal("Restore/Unverified", Assert.Single(result.Items).RevalidationVerdict);
    }

    [Fact]
    public async Task Restore_Quote_Stripped_From_Args()
    {
        var process = new FakeProcess();
        var lists = new Queue<IReadOnlyList<QuarantineRecord>>([[Listed("a\"b")], []]);
        var executor = ExecutorFor(process, new CapturingAudit(), () => lists.Dequeue());

        await executor.ExecuteAsync(
            Request(RestoreTarget("a\"b")),
            CancellationToken.None);

        Assert.Equal("-Restore -Name \"ab\"", Assert.Single(process.Calls).Args);
    }

    [Fact]
    public async Task Restore_Cancel_Before_Start_Stays_Quarantined()
    {
        var process = new FakeProcess();
        var executor = ExecutorFor(process, new CapturingAudit(),
            reader: () => [Listed("Evil")]);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var result = await executor.ExecuteAsync(
            Request(RestoreTarget("Evil")),
            cts.Token);

        Assert.Equal(BatchStatus.Cancelled, result.Status);
        Assert.Equal(ItemStatus.Cancelled, Assert.Single(result.Items).Status);
        Assert.Empty(process.Calls);
    }

    // ---- plan ----

    [Fact]
    public void Plan_Valid_Names_Exact_Command()
    {
        string dir = Path.Combine(_root, "defender");
        Directory.CreateDirectory(dir);
        File.WriteAllBytes(Path.Combine(dir, "MpCmdRun.exe"), [0x4D, 0x5A]);
        var plan = QuarantineRestore.Plan(
            new QuarantineRestoreRequest("Evil:Win32/X"), exeOverrideDir: dir);

        Assert.True(plan.Ready);
        Assert.Contains("-Restore -Name \"Evil:Win32/X\"", plan.CommandLine);
    }

    [Fact]
    public void Plan_BlankName_NotReady()
    {
        var plan = QuarantineRestore.Plan(new QuarantineRestoreRequest("  "));

        Assert.False(plan.Ready);
        Assert.Contains("Nothing was started", plan.Detail);
    }

    [Fact]
    public void Plan_MissingTool_NotReady()
    {
        var plan = QuarantineRestore.Plan(new QuarantineRestoreRequest("Evil"),
            exeOverrideDir: Path.Combine(_root, "no-defender-here"));

        Assert.False(plan.Ready);
        Assert.Contains("not found", plan.Detail);
    }

    // ---- sheet ----

    [Fact]
    public void Sheet_Lines_NameTargetCommandAndBoundary()
    {
        var plan = new QuarantineRestorePlan(
            "Evil", "MpCmdRun.exe -Restore -Name \"Evil\"", true, "planned");
        var sheet = new QuarantineSheetViewModel(plan, "because reasons", Template(), () => null!);

        Assert.Contains("Evil", sheet.TargetLine);
        Assert.Contains("-Restore -Name", sheet.CommandLine);
        Assert.Equal("because reasons", sheet.ExplanationLine);
        Assert.Contains("cannot put it back", sheet.ReversibilityLine);
        Assert.False(sheet.ConfirmCommand.CanExecute(null));
        sheet.Understood = true;
        Assert.True(sheet.ConfirmCommand.CanExecute(null));
    }

    [Fact]
    public void Sheet_RefusedPreview_DisablesConfirm()
    {
        var plan = new QuarantineRestorePlan("Evil", "MpCmdRun.exe", false, "tool missing");
        var sheet = new QuarantineSheetViewModel(plan, "why", Template(), () => null!);

        Assert.True(sheet.IsRefusedPreview);
        sheet.Understood = true;
        Assert.False(sheet.ConfirmCommand.CanExecute(null));
    }

    [Fact]
    public async Task Sheet_Run_BuildsRestoreApproval()
    {
        var plan = new QuarantineRestorePlan(
            "Evil", "MpCmdRun.exe -Restore -Name \"Evil\"", true, "planned");
        var executor = new FakeExecutor();
        var sheet = new QuarantineSheetViewModel(
            plan, "why", Template(), () => DispatcherWith(executor));

        await sheet.RunAsync();

        Assert.True(sheet.IsDone);
        Assert.Equal("Restore done", sheet.OutcomeTitle);
        var target = Assert.Single(Assert.Single(executor.Seen).Targets);
        Assert.Equal("quarantine", target.Kind);
        Assert.Equal(RiskTier.Review, target.ApprovedTier);
        var aux = QuarantineRestoreAux.Parse(target.AuxJson);
        Assert.NotNull(aux);
        Assert.Equal("Evil", aux.Name);
    }

    [Fact]
    public async Task Sheet_RefusedOutcome_Titled()
    {
        var plan = new QuarantineRestorePlan("Evil", "MpCmdRun.exe", true, "planned");
        var executor = new FakeExecutor
        {
            Handler = request => new BatchExecutionResult(BatchStatus.Refused,
                request.Approval.Targets
                    .Select(t => new ItemOutcome(t, ItemStatus.Refused, "nope", "X", null, false))
                    .ToList(),
                "refused"),
        };
        var sheet = new QuarantineSheetViewModel(
            plan, "why", Template(), () => DispatcherWith(executor));

        await sheet.RunAsync();

        Assert.Equal("No restore done", sheet.OutcomeTitle);
    }

    // ---- page ----

    [Fact]
    public void Page_BeginRestore_WithoutHost_StaysNote()
    {
        var vm = new ThreatsViewModel();
        var row = new QuarantineRow("Evil", "Evil", @"C:\x", "today", "why");

        vm.BeginRestore(row);

        // Host carries MpCmdRun, so the plan is Ready and the note
        // names the missing confirmation (nothing started).
        Assert.Contains("Restore confirmation is unavailable", vm.QuarantineActionNote);
        Assert.DoesNotContain("Confirm â€”", vm.QuarantineActionNote);
    }

    [Fact]
    public void Page_BeginRestore_WithHost_ShowsSheet()
    {
        var quarantineHost = new CapturingQuarantineHost();
        var services = new ThreatActionServices(
            () => DispatcherWith(new FakeExecutor()),
            new NoopScanHost(), null, quarantineHost);
        var vm = new ThreatsViewModel(services);
        var row = new QuarantineRow("Evil", "Evil", @"C:\x", "today", "why");

        Assert.True(vm.RestoreActionsAvailable);
        vm.BeginRestore(row);

        var sheet = Assert.Single(quarantineHost.Shown);
        Assert.Contains("Evil", sheet.TargetLine);
        Assert.Equal("why", sheet.ExplanationLine);
    }

    [Fact]
    public void Page_NoteKeep_Changes_Nothing()
    {
        var vm = new ThreatsViewModel();
        vm.NoteKeep(new QuarantineRow("Evil", "Evil", @"C:\x", "today", "why"));

        Assert.Contains("stays in quarantine", vm.QuarantineActionNote);
        Assert.Contains("nothing changed", vm.QuarantineActionNote);
    }

    [Fact]
    public void Page_ExplainQuarantine_Matched_And_Unmatched()
    {
        var history = new List<DefenderDetectionRecord>
        {
            new("Evil:Win32/X", 1, "High", "Trojan", @"C:\x",
                new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc),
                "Quarantined", false),
        };

        string matched = ThreatsViewModel.ExplainQuarantine(
            new QuarantineRecord("Evil:Win32/X", "Evil:Win32/X", @"C:\x", "d", "raw"), history);
        Assert.Contains("High", matched);
        Assert.Contains("Quarantined", matched);

        string unmatched = ThreatsViewModel.ExplainQuarantine(
            new QuarantineRecord("Other", "Other", null, null, "raw"), history);
        Assert.Contains("no matching detection record", unmatched);
        Assert.Contains("The listing is what counts", unmatched);
    }

    [Fact]
    public void Page_SubmissionUrl_Is_Fixed_Https()
    {
        Assert.StartsWith("https://", ThreatsViewModel.MicrosoftSubmissionUrl);
        Assert.Contains("microsoft.com", ThreatsViewModel.MicrosoftSubmissionUrl);
    }
}
