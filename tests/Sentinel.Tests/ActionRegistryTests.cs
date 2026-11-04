using Sentinel.App.Services;
using Sentinel.Engine.Actions;
using Sentinel.Engine.Agent;
using Sentinel.Engine.Policy;
using Sentinel.Engine.Scan;

namespace Sentinel.Tests;

// E30: the action registry + dispatcher. Deny by default, every
// refusal audited, executors only for Active templates, and the AI
// inspection tools provably disjoint from every template ID.
public sealed class ActionRegistryTests : IDisposable
{
    private readonly string _root;
    private bool _disposed;

    public ActionRegistryTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "sentinel-e30-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
        File.WriteAllText(Path.Combine(_root, "junk.tmp"), "junk");
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

    private sealed class CapturingAudit : IActionAuditSink
    {
        public List<AuditDraft> Drafts { get; } = [];

        public bool Fail { get; set; }

        public bool TryAppend(AuditDraft draft, out long seq, out string error)
        {
            if (Fail)
            {
                seq = -1;
                error = "store unavailable";
                return false;
            }

            Drafts.Add(draft);
            seq = Drafts.Count;
            error = string.Empty;
            return true;
        }
    }

    private sealed class FixedLevels : IPermissionLevels
    {
        private readonly Dictionary<string, PermissionLevel> _levels;

        public FixedLevels(Dictionary<string, PermissionLevel>? levels = null)
        {
            _levels = levels ?? new Dictionary<string, PermissionLevel>();
        }

        public PermissionLevel LevelFor(string module) =>
            _levels.TryGetValue(module, out var level) ? level : PermissionLevel.L0;
    }

    private sealed class FakeExecutor : IActionExecutor
    {
        public int Calls { get; private set; }

        public Func<BatchExecutionRequest, BatchExecutionResult>? Handler { get; set; }

        public Task<BatchExecutionResult> ExecuteAsync(
            BatchExecutionRequest request, CancellationToken ct)
        {
            Calls++;
            if (Handler is not null)
            {
                return Task.FromResult(Handler(request));
            }

            var items = request.Approval.Targets
                .Select(t => new ItemOutcome(t, ItemStatus.Done, "fake done", null, null, false))
                .ToList();
            return Task.FromResult(new BatchExecutionResult(BatchStatus.Completed, items, null));
        }
    }

    private ActionApproval Approval(
        string templateId = "clean_items_to_vault",
        string actor = ActionActors.User,
        DateTimeOffset? approvedUtc = null,
        string? key = null,
        int targets = 1)
    {
        var list = new List<ActionTarget>();
        for (int i = 0; i < targets; i++)
        {
            list.Add(new ActionTarget(
                "f:" + (i + 1), Path.Combine(_root, "junk.tmp"), "file",
                RiskTier.Safe, 4, DateTime.UtcNow.Ticks, null));
        }

        return new ActionApproval(templateId, list, [_root], [],
            1, approvedUtc ?? DateTimeOffset.UtcNow,
            actor, key ?? Guid.NewGuid().ToString("N"));
    }

    [Fact]
    public void Registry_ContainsExactlyTwelveTemplates()
    {
        var ids = ActionRegistry.All.Select(t => t.Id).OrderBy(id => id).ToList();
        Assert.Equal(12, ids.Count);
        Assert.Equal(
        [
            "clean_items_to_vault",
            "create_restore_point",
            "defender_scan",
            "disable_startup_item",
            "driver_rollback",
            "driver_update_from_ladder",
            "enable_startup_item",
            "export_report",
            "quarantine_file_via_defender",
            "quarantine_restore",
            "second_opinion_file_check",
            "update_knowledge_pack",
        ], ids);
    }

    [Fact]
    public void Registry_ActiveTemplates_AreCleanDriversScanAndRestore()
    {
        // D42 + T50 + T52 (GOAL-authorized): clean, the driver
        // pair, defender_scan, and quarantine_restore are Active.
        // Everything else stays Registered/Suspended/Proposed.
        var active = ActionRegistry.All
            .Where(t => t.Status == TemplateStatus.Active)
            .Select(t => t.Id)
            .OrderBy(id => id)
            .ToList();
        Assert.Equal(
        [
            "clean_items_to_vault",
            "defender_scan",
            "driver_rollback",
            "driver_update_from_ladder",
            "quarantine_restore",
        ], active);
    }

    [Theory]
    [InlineData("disable_startup_item", TemplateStatus.Suspended)]
    [InlineData("enable_startup_item", TemplateStatus.Suspended)]
    [InlineData("driver_update_from_ladder", TemplateStatus.Active)]
    [InlineData("driver_rollback", TemplateStatus.Active)]
    [InlineData("defender_scan", TemplateStatus.Active)]
    [InlineData("quarantine_restore", TemplateStatus.Active)]
    [InlineData("create_restore_point", TemplateStatus.Registered)]
    [InlineData("export_report", TemplateStatus.Registered)]
    [InlineData("update_knowledge_pack", TemplateStatus.Registered)]
    [InlineData("quarantine_file_via_defender", TemplateStatus.Proposed)]
    [InlineData("second_opinion_file_check", TemplateStatus.Proposed)]
    public void Registry_NonCleanTemplates_HaveExpectedStatus(string id, TemplateStatus status)
    {
        Assert.Equal(status, ActionRegistry.Find(id)?.Status);
    }

    [Theory]
    [InlineData("orphan_registry_cleanup")]
    [InlineData("kill_process")]
    [InlineData("format_drive")]
    [InlineData("clean_items_to_vault ")]
    [InlineData("CLEAN_ITEMS_TO_VAULT")]
    [InlineData("")]
    [InlineData(null)]
    public void Registry_UnknownIds_AreNotFound(string? id)
    {
        Assert.Null(ActionRegistry.Find(id));
        Assert.False(ActionRegistry.IsKnown(id));
    }

    [Fact]
    public void Registry_CleanTemplate_CarriesFullContract()
    {
        var clean = ActionRegistry.Find("clean_items_to_vault");
        Assert.NotNull(clean);
        Assert.Equal("Cleaner", clean.Module);
        Assert.Equal(PermissionLevel.L2, clean.MinLevel);
        Assert.False(clean.RequiresElevation);
        Assert.False(clean.RequiresRestorePoint);
        Assert.NotEmpty(clean.BackupKind);
        Assert.NotEmpty(clean.VerifyStep);
        Assert.NotEmpty(clean.RollbackStep);
    }

    [Theory]
    [InlineData("driver_update_from_ladder")]
    [InlineData("driver_rollback")]
    public void Registry_DriverTemplates_RequireElevationAndRestorePoint(string id)
    {
        var template = ActionRegistry.Find(id);
        Assert.NotNull(template);
        Assert.True(template.RequiresElevation);
        Assert.True(template.RequiresRestorePoint);
        Assert.Equal("Drivers", template.Module);
    }

    [Fact]
    public async Task Dispatch_UnknownTemplate_RefusedAndAuditedWithActor()
    {
        var audit = new CapturingAudit();
        var dispatcher = new ActionDispatcher(audit, new FixedLevels());

        var outcome = await dispatcher.DispatchAsync(
            Approval("kill_process", ActionActors.Scheduled), null, CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, outcome.Status);
        Assert.Equal(RefusalCode.TemplateUnknown, outcome.Refusal);
        Assert.Contains("not a known action", outcome.Detail);
        var draft = Assert.Single(audit.Drafts);
        Assert.Equal("kill_process", draft.ActionId);
        Assert.Equal(ActionActors.Scheduled, draft.Actor);
        Assert.Equal("NotApplicable", draft.UndoState);
    }

    [Theory]
    [InlineData("disable_startup_item", RefusalCode.TemplateSuspended)]
    [InlineData("enable_startup_item", RefusalCode.TemplateSuspended)]
    [InlineData("quarantine_file_via_defender", RefusalCode.TemplateProposed)]
    [InlineData("second_opinion_file_check", RefusalCode.TemplateProposed)]
    [InlineData("export_report", RefusalCode.TemplateNotImplemented)]
    public async Task Dispatch_NonActiveTemplates_RefusedWithDistinctCodes(
        string templateId, RefusalCode refusal)
    {
        var audit = new CapturingAudit();
        var dispatcher = new ActionDispatcher(audit, new FixedLevels(
            new Dictionary<string, PermissionLevel> { ["Cleaner"] = PermissionLevel.L3, ["Drivers"] = PermissionLevel.L2, ["Threats"] = PermissionLevel.L2, ["Startup"] = PermissionLevel.L2, ["System"] = PermissionLevel.L2 }));

        var outcome = await dispatcher.DispatchAsync(
            Approval(templateId), null, CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, outcome.Status);
        Assert.Equal(refusal, outcome.Refusal);
        Assert.Single(audit.Drafts);
    }

    [Fact]
    public async Task Dispatch_EmptyBatch_Refused()
    {
        var audit = new CapturingAudit();
        var dispatcher = new ActionDispatcher(audit, new FixedLevels(
            new Dictionary<string, PermissionLevel> { ["Cleaner"] = PermissionLevel.L2 }));

        var outcome = await dispatcher.DispatchAsync(
            Approval(targets: 0), null, CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, outcome.Status);
        Assert.Equal(RefusalCode.BatchEmpty, outcome.Refusal);
    }

    [Fact]
    public async Task Dispatch_PermissionDenied_WhenBelowMin_ExecutorNeverRuns()
    {
        var audit = new CapturingAudit();
        var executor = new FakeExecutor();
        var dispatcher = new ActionDispatcher(audit, new FixedLevels(
            new Dictionary<string, PermissionLevel> { ["Cleaner"] = PermissionLevel.L1 }));
        Assert.True(dispatcher.RegisterExecutor("clean_items_to_vault", executor));

        var outcome = await dispatcher.DispatchAsync(
            Approval(), null, CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, outcome.Status);
        Assert.Equal(RefusalCode.PermissionDenied, outcome.Refusal);
        Assert.Contains("L1", outcome.Detail);
        Assert.Equal(0, executor.Calls);
        Assert.Single(audit.Drafts);
    }

    [Fact]
    public async Task Dispatch_Allowed_AtMinLevel_ExecutorRuns()
    {
        var audit = new CapturingAudit();
        var executor = new FakeExecutor();
        var dispatcher = new ActionDispatcher(audit, new FixedLevels(
            new Dictionary<string, PermissionLevel> { ["Cleaner"] = PermissionLevel.L2 }));
        Assert.True(dispatcher.RegisterExecutor("clean_items_to_vault", executor));

        var outcome = await dispatcher.DispatchAsync(
            Approval(), null, CancellationToken.None);

        Assert.Equal(BatchStatus.Completed, outcome.Status);
        Assert.Equal(RefusalCode.None, outcome.Refusal);
        Assert.Equal(1, executor.Calls);
        Assert.Single(audit.Drafts);
    }

    [Fact]
    public async Task Dispatch_ExpiredApproval_Refused()
    {
        var audit = new CapturingAudit();
        var executor = new FakeExecutor();
        var dispatcher = new ActionDispatcher(audit, new FixedLevels(
            new Dictionary<string, PermissionLevel> { ["Cleaner"] = PermissionLevel.L2 }));
        Assert.True(dispatcher.RegisterExecutor("clean_items_to_vault", executor));

        var outcome = await dispatcher.DispatchAsync(
            Approval(approvedUtc: DateTimeOffset.UtcNow - ActionDispatcher.ApprovalTtl - TimeSpan.FromMinutes(1)),
            null, CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, outcome.Status);
        Assert.Equal(RefusalCode.ApprovalExpired, outcome.Refusal);
        Assert.Equal(0, executor.Calls);
    }

    [Fact]
    public async Task Dispatch_FreshApproval_Runs()
    {
        var audit = new CapturingAudit();
        var executor = new FakeExecutor();
        var dispatcher = new ActionDispatcher(audit, new FixedLevels(
            new Dictionary<string, PermissionLevel> { ["Cleaner"] = PermissionLevel.L2 }));
        Assert.True(dispatcher.RegisterExecutor("clean_items_to_vault", executor));

        var outcome = await dispatcher.DispatchAsync(
            Approval(approvedUtc: DateTimeOffset.UtcNow - ActionDispatcher.ApprovalTtl + TimeSpan.FromMinutes(1)),
            null, CancellationToken.None);

        Assert.Equal(BatchStatus.Completed, outcome.Status);
        Assert.Equal(1, executor.Calls);
    }

    [Fact]
    public async Task Dispatch_DuplicateKey_RunsExactlyOnce()
    {
        var audit = new CapturingAudit();
        var executor = new FakeExecutor();
        var dispatcher = new ActionDispatcher(audit, new FixedLevels(
            new Dictionary<string, PermissionLevel> { ["Cleaner"] = PermissionLevel.L2 }));
        Assert.True(dispatcher.RegisterExecutor("clean_items_to_vault", executor));

        string key = Guid.NewGuid().ToString("N");
        var first = await dispatcher.DispatchAsync(
            Approval(key: key), null, CancellationToken.None);
        var second = await dispatcher.DispatchAsync(
            Approval(key: key), null, CancellationToken.None);

        Assert.Equal(BatchStatus.Completed, first.Status);
        Assert.Equal(BatchStatus.Duplicate, second.Status);
        Assert.Equal(1, executor.Calls);
        Assert.Equal(2, audit.Drafts.Count);
    }

    [Fact]
    public async Task Dispatch_DistinctKeys_RunIndependently()
    {
        var audit = new CapturingAudit();
        var executor = new FakeExecutor();
        var dispatcher = new ActionDispatcher(audit, new FixedLevels(
            new Dictionary<string, PermissionLevel> { ["Cleaner"] = PermissionLevel.L2 }));
        Assert.True(dispatcher.RegisterExecutor("clean_items_to_vault", executor));

        await dispatcher.DispatchAsync(Approval(), null, CancellationToken.None);
        await dispatcher.DispatchAsync(Approval(), null, CancellationToken.None);

        Assert.Equal(2, executor.Calls);
    }

    [Fact]
    public void RegisterExecutor_RejectsEveryNonActiveTemplate()
    {
        var dispatcher = new ActionDispatcher(new CapturingAudit(), new FixedLevels());
        foreach (var template in ActionRegistry.All)
        {
            bool accepted = dispatcher.RegisterExecutor(template.Id, new FakeExecutor());
            Assert.Equal(template.Status == TemplateStatus.Active, accepted);
        }
    }

    [Fact]
    public async Task Dispatch_PreCancelledToken_CancelsBeforeStart()
    {
        var audit = new CapturingAudit();
        var executor = new FakeExecutor();
        var dispatcher = new ActionDispatcher(audit, new FixedLevels(
            new Dictionary<string, PermissionLevel> { ["Cleaner"] = PermissionLevel.L2 }));
        Assert.True(dispatcher.RegisterExecutor("clean_items_to_vault", executor));

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var outcome = await dispatcher.DispatchAsync(Approval(), null, cts.Token);

        Assert.Equal(BatchStatus.Cancelled, outcome.Status);
        Assert.Equal(0, executor.Calls);
    }

    [Fact]
    public async Task Dispatch_ExecutorThrow_MapsToFailedOutcome()
    {
        var audit = new CapturingAudit();
        var executor = new FakeExecutor
        {
            Handler = _ => throw new InvalidOperationException("boom"),
        };
        var dispatcher = new ActionDispatcher(audit, new FixedLevels(
            new Dictionary<string, PermissionLevel> { ["Cleaner"] = PermissionLevel.L2 }));
        Assert.True(dispatcher.RegisterExecutor("clean_items_to_vault", executor));

        var outcome = await dispatcher.DispatchAsync(
            Approval(), null, CancellationToken.None);

        Assert.Equal(BatchStatus.Failed, outcome.Status);
        Assert.Contains("InvalidOperationException", outcome.Detail);
    }

    [Fact]
    public async Task Dispatch_AuditFailure_WarnsFailClosed()
    {
        var audit = new CapturingAudit { Fail = true };
        var dispatcher = new ActionDispatcher(audit, new FixedLevels());

        var outcome = await dispatcher.DispatchAsync(
            Approval("kill_process"), null, CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, outcome.Status);
        Assert.Equal(-1, outcome.AuditSeq);
        Assert.Contains("WARNING", outcome.Detail);
        Assert.Contains("audit log", outcome.Detail);
    }

    [Fact]
    public void Provider_UnknownModule_AnswersL0()
    {
        var provider = new SettingsPermissionLevels(() => SentinelSettings.Defaults);
        Assert.Equal(PermissionLevel.L0, provider.LevelFor("Nope"));
        Assert.Equal(PermissionLevel.L0, provider.LevelFor(string.Empty));
    }

    [Fact]
    public void Provider_DriversAndThreats_CappedAtL2()
    {
        var raised = SentinelSettings.Defaults with { DriversPermission = 3, ThreatsPermission = 3 };
        var provider = new SettingsPermissionLevels(() => raised);
        Assert.Equal(PermissionLevel.L2, provider.LevelFor("Drivers"));
        Assert.Equal(PermissionLevel.L2, provider.LevelFor("Threats"));
    }

    [Fact]
    public void Provider_CleanerL3_AllowedWhenConfigured()
    {
        var raised = SentinelSettings.Defaults with { CleanerPermission = 3 };
        var provider = new SettingsPermissionLevels(() => raised);
        Assert.Equal(PermissionLevel.L3, provider.LevelFor("Cleaner"));
    }

    [Fact]
    public void Provider_Defaults_AreL2Everywhere()
    {
        var provider = new SettingsPermissionLevels(() => SentinelSettings.Defaults);
        foreach (string module in new[] { "Cleaner", "Drivers", "Threats", "Startup", "Performance", "System" })
        {
            Assert.Equal(PermissionLevel.L2, provider.LevelFor(module));
        }
    }

    [Fact]
    public void Settings_Sanitize_ClampsPermissionLevels()
    {
        var wild = SentinelSettings.Defaults with { CleanerPermission = 9, DriversPermission = -4 };
        var clean = wild.Sanitized();
        Assert.Equal(3, clean.CleanerPermission);
        Assert.Equal(0, clean.DriversPermission);
    }

    [Fact]
    public void Settings_LegacyJson_MissingPermissionKeys_DefaultL2()
    {
        string path = Path.Combine(_root, "legacy-settings.json");
        File.WriteAllText(path, """
            {"DefaultScanMode":"Eco","BalancedCapPercent":20,"AiEnabled":false,
             "NeverTouch":[],"Theme":"Light","FontScale":1.0}
            """);
        var loaded = new SettingsStore(path).Load();
        Assert.Equal("Eco", loaded.DefaultScanMode);
        var provider = new SettingsPermissionLevels(() => loaded);
        Assert.Equal(PermissionLevel.L2, provider.LevelFor("Cleaner"));
        Assert.Equal(PermissionLevel.L2, provider.LevelFor("Drivers"));
    }

    [Fact]
    public void ZeroMutationPath_ProductionToolNames_AreDisjointFromTemplateIds()
    {
        // The production registration, exactly as ScanSessionViewModel
        // builds it: StorageTools.All + ExcerptTools + EventTools.
        var hub = new EvidencePreviewHub();
        var names = new StorageTools(hub, null).All.Select(t => t.Name).ToList();
        names.Add(new ExcerptTools(hub).Name);
        names.Add(new EventTools(hub).Name);

        Assert.NotEmpty(names);
        var templateIds = ActionRegistry.All.Select(t => t.Id).ToHashSet(StringComparer.Ordinal);
        foreach (string name in names)
        {
            Assert.False(templateIds.Contains(name),
                $"AI tool '{name}' collides with an action template ID.");
        }
    }
}
