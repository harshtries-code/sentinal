using System.Text.RegularExpressions;
using System.Threading;
using Sentinel.Engine.Agent;
using Sentinel.Engine.Scan;
using Sentinel.Store;

namespace Sentinel.Tests;

// M2 (10): the investigation runs CONCURRENTLY with a real scan.
// A test-double model explores branches through tools only — no
// hardcoded paths — while collection is provably unfinished.
public sealed class AgentIntegrationTests : IDisposable
{
    private readonly string _root;
    private readonly string _dbPath;
    private readonly string _agentDbPath;
    private bool _disposed;

    public AgentIntegrationTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "sentinel-m2-" + Guid.NewGuid().ToString("N"));
        _dbPath = Path.Combine(Path.GetTempPath(), "sentinel-m2-" + Guid.NewGuid().ToString("N") + ".db");
        _agentDbPath = Path.Combine(Path.GetTempPath(), "sentinel-m2-" + Guid.NewGuid().ToString("N") + ".adb");
    }

    // Explores purely through tool outputs: lists every discovered
    // directory ID, inspects every discovered file ID, then cites
    // the first inspected file. Knows NO names in advance.
    private sealed class FixedIdle : IIdleProbe
    {
        private readonly TimeSpan _idle;

        public FixedIdle(TimeSpan idle)
        {
            _idle = idle;
        }

        public TimeSpan GetIdleTime() => _idle;
    }

    private sealed class FixedFullscreen : IFullscreenProbe
    {
        private readonly bool _fullscreen;

        public FixedFullscreen(bool fullscreen)
        {
            _fullscreen = fullscreen;
        }

        public bool IsForegroundFullscreen() => _fullscreen;
    }

    private sealed class ExploringModel : IInvestigationModel
    {
        private readonly HashSet<string> _listed = new(StringComparer.Ordinal);
        private readonly List<string> _inspected = new();
        private bool _emitted;
        private int _turns;

        public string Name => "exploring-test-double";

        public List<string> ContextsSeen { get; } = new();

        public Task<ModelTurn> GetNextStepAsync(string contextJson, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            ContextsSeen.Add(contextJson);
            _turns++;
            if (_turns > 30)
            {
                return Task.FromResult(new ModelTurn(null, null, true, "Turn cap."));
            }

            var ids = Regex.Matches(contextJson, @"[fd]:\d+")
                .Select(m => m.Value).Distinct().ToList();
            var dir = ids.FirstOrDefault(id => id.StartsWith("d:") && !_listed.Contains(id));
            if (dir is not null)
            {
                _listed.Add(dir);
                return Task.FromResult(new ModelTurn(
                    new ToolCallRequest("list_directory", new Dictionary<string, string>
                    {
                        ["dir_id"] = dir,
                        ["limit"] = "50",
                    }),
                    null, false, null));
            }

            // Conclude after the FIRST inspection: the milestone proves
            // tool-driven discovery + citation, not exhaustive review.
            if (!_emitted && _inspected.Count == 0)
            {
                var file = ids.FirstOrDefault(id => id.StartsWith("f:") && !_inspected.Contains(id));
                if (file is not null)
                {
                    _inspected.Add(file);
                    return Task.FromResult(new ModelTurn(
                        new ToolCallRequest("inspect_file", new Dictionary<string, string>
                        {
                            ["file_id"] = file,
                        }),
                        null, false, null));
                }
            }

            if (!_emitted && _inspected.Count > 0)
            {
                _emitted = true;
                return Task.FromResult(new ModelTurn(null, new FindingDraft(
                    "Discovered a file inside an explored branch.",
                    "Test-double interpretation.",
                    [_inspected[0]],
                    "Unreconciled at emission.",
                    "reconcile at final coverage"), false, null));
            }

            return Task.FromResult(new ModelTurn(null, null, true, "Explored."));
        }
    }

    private static ToolBroker FullBroker(EvidencePreviewHub hub, AgentStore store, SentinelDb? db)
    {
        var broker = new ToolBroker(store);
        foreach (var tool in new StorageTools(hub, db).All)
        {
            broker.Register(tool);
        }

        broker.Register(new ExcerptTools(hub));
        broker.Register(new EventTools(hub));
        return broker;
    }

    private void BuildBranchFixture(int perBranch = 200)
    {
        // Root holds ONLY branches: every discovered file is inside
        // a branch the model reached through tools.
        var payload = new byte[1024];
        new Random(11).NextBytes(payload);
        foreach (var branch in new[] { "branch-a", "branch-b", "logs" })
        {
            var dir = Path.Combine(_root, branch);
            Directory.CreateDirectory(dir);
            for (int i = 0; i < perBranch; i++)
            {
                File.WriteAllBytes(Path.Combine(dir, $"w{i:D3}.bin"), payload);
            }
        }
    }

    [Fact]
    public async Task UnflaggedBranch_Explored_Before_Collection_Finishes()
    {
        BuildBranchFixture();
        using var db = new SentinelDb(_dbPath);
        using var agentStore = new AgentStore(_agentDbPath);
        var orchestrator = new ScanOrchestrator(
            db,
            idle: new FixedIdle(TimeSpan.FromMinutes(30)),
            fullscreen: new FixedFullscreen(false));
        var hub = new EvidencePreviewHub();
        var pause = new PauseToken();
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));

        var scanTask = orchestrator.RunAsync(
            new ScanOptions(ScanMode.Balanced, [_root]), pause, cts.Token, hub);
        Assert.True(
            SpinWait.SpinUntil(() => hub.Revision > 0, TimeSpan.FromSeconds(30)),
            "Scan produced no preview evidence.");
        pause.Pause();
        await Task.Delay(300, CancellationToken.None); // In-flight workers reach the gate.

        var broker = FullBroker(hub, agentStore, db);
        broker.MintDirId(_root);
        var model = new ExploringModel();
        var coordinator = new InvestigationCoordinator(
            Guid.NewGuid().ToString("N"), [_root], "Explore mid-scan.",
            hub, broker, model, agentStore,
            new InvestigationBudgets(), new PayloadLog());
        var status = await coordinator.RunAsync(cts.Token);

        // The scan MUST still be unfinished: findings are provisional.
        Assert.False(scanTask.IsCompleted);
        Assert.False(hub.IsComplete);
        Assert.Equal(InvestigationStatus.Done, status);
        Assert.NotEmpty(model.ContextsSeen);
        Assert.Contains(
            model.ContextsSeen,
            c => Regex.IsMatch(c, @"collection_complete.{0,6}False"));
        var finding = Assert.Single(coordinator.Findings);
        Assert.Equal(FindingStatus.Provisional, finding.Status);
        var cited = Assert.Single(finding.Evidence);
        Assert.StartsWith(_root, cited.Path, StringComparison.OrdinalIgnoreCase);
        Assert.NotEqual(
            _root.TrimEnd(Path.DirectorySeparatorChar),
            Path.GetDirectoryName(cited.Path)); // Inside an explored branch.
        Assert.True(agentStore.CountToolAudits(
            coordinator.InvestigationId, true) >= 5);

        pause.Resume();
        var scan = await scanTask;
        Assert.Equal(ScanOutcome.Completed, scan.Outcome);
        await coordinator.ReconcileAsync(db, scan.Generation, cts.Token);
        Assert.Equal(FindingStatus.Confirmed, coordinator.Findings.Single().Status);
    }

    [Fact]
    public async Task CloseReopen_Resumes_Cold_And_Reconciles()
    {
        BuildBranchFixture(perBranch: 20);
        using var db = new SentinelDb(_dbPath);
        var orchestrator = new ScanOrchestrator(
            db,
            idle: new FixedIdle(TimeSpan.FromMinutes(30)),
            fullscreen: new FixedFullscreen(false));
        var hub = new EvidencePreviewHub();
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        var scan = await orchestrator.RunAsync(
            new ScanOptions(ScanMode.Balanced, [_root]), new PauseToken(), cts.Token, hub);
        Assert.Equal(ScanOutcome.Completed, scan.Outcome);

        string invId;
        using (var agentStore = new AgentStore(_agentDbPath))
        {
            var broker = FullBroker(hub, agentStore, db);
            broker.MintDirId(_root);
            var coordinator = new InvestigationCoordinator(
                Guid.NewGuid().ToString("N"), [_root], "Find one file.",
                hub, broker, new ExploringModel(), agentStore,
                new InvestigationBudgets(), new PayloadLog());
            invId = coordinator.InvestigationId;
            Assert.Equal(InvestigationStatus.Done, await coordinator.RunAsync(cts.Token));
            Assert.Single(coordinator.Findings);
        } // CLOSE: coordinator, hub, broker, store all dropped.

        // REOPEN: empty hub, fresh ID maps, same durable store file.
        // No model history survives: the cache-eviction case.
        using var reopened = new AgentStore(_agentDbPath);
        var coldHub = new EvidencePreviewHub();
        var coldBroker = FullBroker(coldHub, reopened, db);
        var resumed = InvestigationCoordinator.Resume(
            reopened, invId, [_root], coldHub, coldBroker,
            new ScriptedModel([]), new InvestigationBudgets(), new PayloadLog());

        Assert.Single(resumed.Findings); // Provisional finding reloaded.
        Assert.Equal(InvestigationStatus.Done, await resumed.RunAsync(cts.Token));
        await resumed.ReconcileAsync(db, scan.Generation, cts.Token);
        Assert.Equal(FindingStatus.Confirmed, resumed.Findings.Single().Status);
        Assert.Contains("1 confirmed", resumed.StatusDetail ?? string.Empty);
    }

    [Fact]
    public async Task StaleEvidence_Invalidates_Finding()
    {
        BuildBranchFixture(perBranch: 5);
        using var db = new SentinelDb(_dbPath);
        using var agentStore = new AgentStore(_agentDbPath);
        var orchestrator = new ScanOrchestrator(
            db,
            idle: new FixedIdle(TimeSpan.FromMinutes(30)),
            fullscreen: new FixedFullscreen(false));
        var hub = new EvidencePreviewHub();
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        var scan = await orchestrator.RunAsync(
            new ScanOptions(ScanMode.Balanced, [_root]), new PauseToken(), cts.Token, hub);

        var broker = FullBroker(hub, agentStore, db);
        broker.MintDirId(_root);
        var coordinator = new InvestigationCoordinator(
            Guid.NewGuid().ToString("N"), [_root], "Find one file.",
            hub, broker, new ExploringModel(), agentStore,
            new InvestigationBudgets(), new PayloadLog());
        await coordinator.RunAsync(cts.Token);
        var cited = Assert.Single(coordinator.Findings).Evidence.Single();

        File.WriteAllBytes(cited.Path, new byte[4096]); // Evidence changes.
        await coordinator.ReconcileAsync(db, scan.Generation, cts.Token);

        Assert.Equal(FindingStatus.Stale, coordinator.Findings.Single().Status);
    }

    [Fact]
    public void QueryEvents_Tool_Returns_Bounded_Envelope()
    {
        using var agentStore = new AgentStore(_agentDbPath);
        var broker = FullBroker(new EvidencePreviewHub(), agentStore, null);
        var scope = new InvestigationScope(Guid.NewGuid().ToString("N"), [_root]);

        var result = broker.Dispatch(
            scope,
            new ToolCallRequest("query_events", new Dictionary<string, string>
            {
                ["channel"] = "System",
                ["limit"] = "3",
                ["since_hours"] = "168",
            }),
            new InvestigationBudgets(),
            CancellationToken.None);

        // Either readable rows or an honest error with gaps — the
        // envelope contract holds in both cases.
        Assert.True(result.Items.Count <= 3);
        Assert.All(result.Items, i =>
        {
            Assert.True(i.Fields.ContainsKey("record_id"));
            Assert.True(i.Fields.ContainsKey("message"));
        });
        if (result.Status == ToolResultStatus.Error)
        {
            Assert.NotEmpty(result.Gaps);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        try { Directory.Delete(_root, recursive: true); } catch { /* best effort */ }
        try { File.Delete(_dbPath); } catch { /* best effort */ }
        try { File.Delete(_agentDbPath); } catch { /* best effort */ }
    }
}
