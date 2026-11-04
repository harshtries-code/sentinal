using Sentinel.App.Services;
using Sentinel.App.ViewModels;
using Sentinel.Engine.Agent;
using Sentinel.Engine.Policy;
using Sentinel.Engine.Scan;
using Sentinel.Store;

namespace Sentinel.Tests;

// A11: data-policy and scope controls. Protected-from-action
// (NeverTouch) and excluded-from-inspection (ExcludedPathPrefixes)
// are SEPARATE mechanisms: protection never prunes enumeration,
// exclusion prunes everywhere (enumeration, broker, excerpts)
// with a visible gap. Scope is canonicalized once and enforced
// at every layer; resume is invalidated when scope changes.
public sealed class ScopePolicyTests : IDisposable
{
    private readonly string _root;
    private readonly string _dbPath;
    private readonly string _agentDbPath;

    public ScopePolicyTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "sentinel-a11-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
        _dbPath = Path.Combine(Path.GetTempPath(), "sentinel-a11-" + Guid.NewGuid().ToString("N") + ".db");
        _agentDbPath = Path.Combine(Path.GetTempPath(), "sentinel-a11-" + Guid.NewGuid().ToString("N") + "-agent.db");
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, true);
        }
        catch
        {
        }

        try
        {
            File.Delete(_dbPath);
        }
        catch
        {
        }

        try
        {
            File.Delete(_agentDbPath);
        }
        catch
        {
        }
    }

    [Fact]
    public async Task FileRoot_InsideExcludedPrefix_YieldsGap_NotFile()
    {
        string sub = Path.Combine(_root, "vault");
        Directory.CreateDirectory(sub);
        string file = Path.Combine(sub, "v.log");
        File.WriteAllText(file, "vault-bytes");
        using var db = new SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(db);
        // A single-file scan root inside an excluded prefix must be
        // refused like any other excluded path — never yielded.
        var options = new ScanOptions(ScanMode.Balanced, [file], excludedPathPrefixes: [sub]);

        var result = await orchestrator.RunAsync(options, new PauseToken());

        Assert.Equal(ScanOutcome.Completed, result.Outcome);
        Assert.Equal(0, result.FilesSeen);
        Assert.Contains(result.Gaps, g => g.Reason == "ExcludedScope");
        Assert.Null(db.GetFingerprint(file));
    }

    [Fact]
    public void Excerpt_ChangedUnderSnapshot_ReturnsStale_NoText()
    {
        string logs = Path.Combine(_root, "logs");
        Directory.CreateDirectory(logs);
        string file = Path.Combine(logs, "app.log");
        File.WriteAllText(file, "first line\n");
        var hub = new EvidencePreviewHub();
        using var store = new AgentStore(_agentDbPath);
        var broker = new ToolBroker(store);
        broker.Register(new ExcerptTools(hub));
        var scope = new InvestigationScope("inv-a11-stale", [_root]);
        string fileId = broker.MintFileId(file);
        // The hub saw the file BEFORE it changed (size 1); the live
        // file is now bigger — the excerpt must go stale, like
        // inspect_file, instead of serving mixed-generation text.
        hub.ObserveFile(file, 1, 0, null);
        File.AppendAllText(file, "second line\n");

        var result = broker.Dispatch(
            scope,
            new ToolCallRequest("read_text_excerpt", new Dictionary<string, string>
            {
                ["file_id"] = fileId,
            }),
            new InvestigationBudgets(),
            CancellationToken.None);

        Assert.Equal(ToolResultStatus.Stale, result.Status);
        Assert.Empty(result.Items);
    }

    [Fact]
    public void Fingerprint_Canonicalization_IgnoresSpelling()
    {
        string a = Path.Combine(_root, "scope");
        string b = Path.Combine(_root, "other");
        Directory.CreateDirectory(a);
        Directory.CreateDirectory(b);

        // Case, trailing separators, dot segments, root order,
        // and null-vs-empty exclusions never change the verdict.
        string plain = ScopeFingerprint.Compute([a, b]);
        string spelled = ScopeFingerprint.Compute(
            [b.ToUpperInvariant() + Path.DirectorySeparatorChar, a + Path.DirectorySeparatorChar + "."],
            []);
        Assert.Equal(plain, spelled);
        Assert.Equal(
            ScopeFingerprint.Compute([a], null),
            ScopeFingerprint.Compute([a], []));
    }

    [Fact]
    public void Fingerprint_Differs_OnRootOrExclusionChange()
    {
        string a = Path.Combine(_root, "scope");
        string b = Path.Combine(_root, "other");
        Directory.CreateDirectory(a);
        Directory.CreateDirectory(b);

        string baseFp = ScopeFingerprint.Compute([a], [b]);
        Assert.NotEqual(baseFp, ScopeFingerprint.Compute([b], [b]));
        Assert.NotEqual(baseFp, ScopeFingerprint.Compute([a], []));
        Assert.NotEqual(baseFp, ScopeFingerprint.Compute([a], [a]));
        Assert.NotEqual(baseFp, ScopeFingerprint.Compute([a, b], [b]));
    }

    [Fact]
    public void ResumeGate_Rules()
    {
        string fp = ScopeFingerprint.Compute([_root]);
        Assert.True(ResumeGate.IsResumable("Investigating", fp, fp));
        Assert.False(ResumeGate.IsResumable("Done", fp, fp));
        Assert.False(ResumeGate.IsResumable("Cancelled", fp, fp));
        Assert.False(ResumeGate.IsResumable("Investigating", null, fp));
        Assert.False(ResumeGate.IsResumable(
            "Investigating", fp, ScopeFingerprint.Compute([_root], [_root])));
    }

    private RiskClassifier TestClassifier(string[]? neverList = null)
    {
        // Faux system layout under the fixture: nothing here
        // depends on the machine's real profile directories.
        return new RiskClassifier(
            Path.Combine(_root, "fauxwin"),
            Path.Combine(_root, "pf"),
            Path.Combine(_root, "pf86"),
            Path.Combine(_root, "pd"),
            Path.Combine(_root, "fauxtemp"),
            Path.Combine(_root, "local"),
            Path.Combine(_root, "roaming"),
            [Path.Combine(_root, "docs")],
            neverList ?? []);
    }

    [Fact]
    public void Revalidate_Ok_WhenTierUnchanged()
    {
        string temp = Path.Combine(_root, "fauxtemp");
        Directory.CreateDirectory(temp);
        string file = Path.Combine(temp, "scratch.tmp");
        File.WriteAllText(file, "scratch");

        var result = ActionRevalidator.Revalidate(
            file, RiskTier.Safe, TestClassifier(),
            new ActionScope([_root], []), DateTime.UtcNow);

        Assert.Equal(ActionRevalidationVerdict.Ok, result.Verdict);
        Assert.Equal(RiskTier.Safe, result.Current.Tier);
    }

    [Fact]
    public void Revalidate_Protected_WhenNeverListed()
    {
        string temp = Path.Combine(_root, "fauxtemp");
        Directory.CreateDirectory(temp);
        string file = Path.Combine(temp, "scratch.tmp");
        File.WriteAllText(file, "scratch");

        // Added to Never Touch after approval: execution-time
        // protection wins over the stale approval.
        var result = ActionRevalidator.Revalidate(
            file, RiskTier.Safe, TestClassifier([temp]),
            new ActionScope([_root], []), DateTime.UtcNow);

        Assert.Equal(ActionRevalidationVerdict.Protected, result.Verdict);
        Assert.Equal(RiskTier.Never, result.Current.Tier);
    }

    [Fact]
    public void Revalidate_TierChanged_WhenDrifted()
    {
        string temp = Path.Combine(_root, "fauxtemp");
        Directory.CreateDirectory(temp);
        string file = Path.Combine(temp, "scratch.tmp");
        File.WriteAllText(file, "scratch");

        var result = ActionRevalidator.Revalidate(
            file, RiskTier.Review, TestClassifier(),
            new ActionScope([_root], []), DateTime.UtcNow);

        Assert.Equal(ActionRevalidationVerdict.TierChanged, result.Verdict);
        Assert.Equal(RiskTier.Safe, result.Current.Tier);
    }

    [Fact]
    public void Revalidate_OutOfScope_Excluded_Unreadable()
    {
        string temp = Path.Combine(_root, "fauxtemp");
        Directory.CreateDirectory(temp);
        string file = Path.Combine(temp, "scratch.tmp");
        File.WriteAllText(file, "scratch");
        var classifier = TestClassifier();
        var now = DateTime.UtcNow;

        var outside = ActionRevalidator.Revalidate(
            file, RiskTier.Safe, classifier,
            new ActionScope([Path.Combine(_root, "elsewhere")], []), now);
        Assert.Equal(ActionRevalidationVerdict.OutOfScope, outside.Verdict);

        var excluded = ActionRevalidator.Revalidate(
            file, RiskTier.Safe, classifier,
            new ActionScope([_root], [temp]), now);
        Assert.Equal(ActionRevalidationVerdict.Excluded, excluded.Verdict);

        File.Delete(file);
        var gone = ActionRevalidator.Revalidate(
            file, RiskTier.Safe, classifier,
            new ActionScope([_root], []), now);
        Assert.Equal(ActionRevalidationVerdict.Unreadable, gone.Verdict);
    }

    [SkippableFact]
    public void Revalidate_LinkRefused_ForSymlink()
    {
        string target = Path.Combine(_root, "real.tmp");
        File.WriteAllText(target, "real");
        string link = Path.Combine(_root, "link.tmp");
        bool created = RunCmd($"mklink \"{link}\" \"{target}\"") && File.Exists(link);
        Skip.IfNot(created, "File symlinks require privilege unavailable here.");

        var result = ActionRevalidator.Revalidate(
            link, RiskTier.Safe, TestClassifier(),
            new ActionScope([_root], []), DateTime.UtcNow);

        Assert.Equal(ActionRevalidationVerdict.LinkRefused, result.Verdict);
    }

    [Fact]
    public async Task NeverTouch_StillInventoried_ButNeverTier()
    {
        // Separation, direction 1: protection-from-action never
        // prunes inspection. The file is inventoried AND tiered NEVER.
        string keep = Path.Combine(_root, "keep");
        Directory.CreateDirectory(keep);
        string file = Path.Combine(keep, "photo.jpg");
        File.WriteAllText(file, "bytes");
        using var db = new SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(db);

        var result = await orchestrator.RunAsync(
            new ScanOptions(ScanMode.Balanced, [_root]), new PauseToken());

        Assert.Equal(ScanOutcome.Completed, result.Outcome);
        var fp = db.GetFingerprint(file);
        Assert.NotNull(fp);
        var label = TestClassifier([keep]).Classify(fp, DateTime.UtcNow);
        Assert.Equal(RiskTier.Never, label.Tier);
        Assert.Contains("N-neverlist", label.RuleIds);
    }

    [Fact]
    public async Task Session_Start_AppliesExcludedProvider()
    {
        string skip = Path.Combine(_root, "skip");
        Directory.CreateDirectory(skip);
        File.WriteAllText(Path.Combine(skip, "s.txt"), "hidden");
        string kept = Path.Combine(_root, "k.txt");
        File.WriteAllText(kept, "kept");
        var session = new ScanSessionViewModel(
            () => new SentinelDb(_dbPath),
            dispatcher: new ImmediateDispatcher(),
            excludedPrefixesProvider: () => [skip]);

        session.Start(ScanMode.Balanced, _root);
        var result = await session.RunningTask!;

        Assert.NotNull(result);
        Assert.Equal(ScanSessionState.Completed, session.State);
        Assert.Contains(session.Gaps, g => g.Reason == "ExcludedScope");
        using var db = new SentinelDb(_dbPath);
        Assert.Null(db.GetFingerprint(Path.Combine(skip, "s.txt")));
        Assert.NotNull(db.GetFingerprint(kept));
    }

    [Fact]
    public void DefaultExclusions_IsOwnDataDirOnly()
    {
        // Separation, direction 2, pinned at the production seam:
        // the default exclusion set is exactly Sentinel's own data
        // dir — NeverTouch entries can never leak in.
        var defaults = ScanSessionViewModel.DefaultExclusions();
        Assert.Single(defaults);
        Assert.Equal(SentinelPaths.DataDirectory, defaults[0]);
    }

    [Fact]
    public void Broker_Denies_Excluded_Inspect_And_Excerpt()
    {
        string skip = Path.Combine(_root, "skip");
        Directory.CreateDirectory(skip);
        string secret = Path.Combine(skip, "secret.log");
        File.WriteAllText(secret, "classified");
        var hub = new EvidencePreviewHub();
        using var store = new AgentStore(_agentDbPath);
        var broker = new ToolBroker(store);
        foreach (var tool in new StorageTools(hub).All)
        {
            broker.Register(tool);
        }

        broker.Register(new ExcerptTools(hub));
        var scope = new InvestigationScope("inv-a11-excl", [_root], [skip]);
        string fileId = broker.MintFileId(secret);
        var budgets = new InvestigationBudgets();

        var inspect = broker.Dispatch(
            scope,
            new ToolCallRequest("inspect_file", new Dictionary<string, string> { ["file_id"] = fileId }),
            budgets,
            CancellationToken.None);
        Assert.Equal(ToolResultStatus.Denied, inspect.Status);
        Assert.Contains(inspect.Gaps, g => g.Reason.StartsWith("ExcludedScope"));

        var excerpt = broker.Dispatch(
            scope,
            new ToolCallRequest("read_text_excerpt", new Dictionary<string, string> { ["file_id"] = fileId }),
            budgets,
            CancellationToken.None);
        Assert.Equal(ToolResultStatus.Denied, excerpt.Status);
        Assert.Empty(excerpt.Items);
        Assert.Contains(excerpt.Gaps, g => g.Reason.StartsWith("ExcludedScope"));
    }

    [Fact]
    public void ListDirectory_Skips_Excluded_WithSummaryGap()
    {
        string skip = Path.Combine(_root, "skip");
        Directory.CreateDirectory(skip);
        File.WriteAllText(Path.Combine(skip, "s.txt"), "hidden");
        File.WriteAllText(Path.Combine(_root, "visible.txt"), "kept");
        var hub = new EvidencePreviewHub();
        using var store = new AgentStore(_agentDbPath);
        var broker = new ToolBroker(store);
        foreach (var tool in new StorageTools(hub).All)
        {
            broker.Register(tool);
        }

        var scope = new InvestigationScope("inv-a11-list", [_root], [skip]);
        string dirId = broker.MintDirId(_root);

        var result = broker.Dispatch(
            scope,
            new ToolCallRequest("list_directory", new Dictionary<string, string> { ["dir_id"] = dirId }),
            new InvestigationBudgets(),
            CancellationToken.None);

        Assert.Equal(ToolResultStatus.Ok, result.Status);
        Assert.DoesNotContain(result.Items, i => i.Fields["name"] == "skip");
        Assert.Contains(result.Items, i => i.Fields["name"] == "visible.txt");
        Assert.Contains(result.Gaps, g => g.Reason == "ExcludedScopeSkipped:1");
    }

    private sealed class DoneModel : IInvestigationModel
    {
        public string Name => "done";

        public Task<ModelTurn> GetNextStepAsync(string contextJson, CancellationToken ct) =>
            Task.FromResult(new ModelTurn(null, null, true, null));
    }

    private static void PlantCheckpoint(AgentStore store, string id, string root, string? fingerprint)
    {
        store.UpsertInvestigation(
            id, root, "test", "Investigating", null, 0, 0,
            0, 0, 0.0, 0, 0, 0, 0, 0, false, null, "[]", fingerprint);
    }

    [Fact]
    public void Resume_MatchingFingerprint_Succeeds()
    {
        using var store = new AgentStore(_agentDbPath);
        PlantCheckpoint(store, "inv-ok", _root, ScopeFingerprint.Compute([_root]));
        var hub = new EvidencePreviewHub();
        var broker = new ToolBroker(store);

        var resumed = InvestigationCoordinator.Resume(
            store, "inv-ok", [_root], hub, broker, new DoneModel(),
            new InvestigationBudgets(), new PayloadLog());

        Assert.Equal("inv-ok", resumed.InvestigationId);
    }

    [Fact]
    public void Resume_ChangedExclusions_ThrowsScopeChanged()
    {
        using var store = new AgentStore(_agentDbPath);
        PlantCheckpoint(store, "inv-drift", _root, ScopeFingerprint.Compute([_root]));
        var hub = new EvidencePreviewHub();
        var broker = new ToolBroker(store);

        var ex = Assert.Throws<InvalidOperationException>(() => InvestigationCoordinator.Resume(
            store, "inv-drift", [_root], hub, broker, new DoneModel(),
            new InvestigationBudgets(), new PayloadLog(), [Path.Combine(_root, "skip")]));

        Assert.Equal("ScopeChanged", ex.Message);
    }

    [Fact]
    public void Resume_LegacyNullFingerprint_ThrowsScopeChanged()
    {
        using var store = new AgentStore(_agentDbPath);
        PlantCheckpoint(store, "inv-legacy", _root, null);
        var hub = new EvidencePreviewHub();
        var broker = new ToolBroker(store);

        var ex = Assert.Throws<InvalidOperationException>(() => InvestigationCoordinator.Resume(
            store, "inv-legacy", [_root], hub, broker, new DoneModel(),
            new InvestigationBudgets(), new PayloadLog()));

        Assert.Equal("ScopeChanged", ex.Message);
    }

    private static bool RunCmd(string args)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c " + args)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
            };
            using var proc = System.Diagnostics.Process.Start(psi)!;
            proc.WaitForExit(15000);
            return proc.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }
}
