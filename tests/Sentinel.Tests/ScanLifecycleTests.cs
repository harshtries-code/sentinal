using System.Net.Http;
using System.Text.RegularExpressions;
using Sentinel.App.Services;
using Sentinel.App.ViewModels;
using Sentinel.Engine.Agent;
using Sentinel.Engine.Scan;
using Sentinel.Store;
using Xunit;

namespace Sentinel.Tests;

// P1-01: desktop scan lifecycle — model factory, provisional flow,
// cancel, resume, reconciliation, and the fake-transport live path.
// Rule: no test uses the VM's DEFAULT model factory (it reads the
// real vault and could go live if the owner ever stores a key).
public sealed class ScanLifecycleTests : IDisposable
{
    private readonly string _dir;
    private readonly string _scope;
    private readonly string _dbPath;
    private readonly string _agentDbPath;

    public ScanLifecycleTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "sentinel-lifecycle-" + Guid.NewGuid().ToString("N"));
        _scope = Path.Combine(_dir, "scope");
        Directory.CreateDirectory(_scope);
        File.WriteAllText(Path.Combine(_scope, "a.txt"), "alpha");
        File.WriteAllText(Path.Combine(_scope, "b.log"), "beta\n");
        File.WriteAllText(Path.Combine(_scope, "c.bin"), "gamma");
        _dbPath = Path.Combine(_dir, "inventory.db");
        _agentDbPath = Path.Combine(_dir, "agent.db");
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, true);
        }
        catch
        {
        }
    }

    private ScanSessionViewModel Session(
        Func<IReadOnlyList<IInvestigationTool>, HttpClient, PayloadLog, InvestigationBudgets, ModelSource> factory,
        Func<HttpClient>? httpFactory = null) =>
        new(() => new SentinelDb(_dbPath), null, new ImmediateDispatcher(),
            () => new AgentStore(_agentDbPath), () => true, factory,
            httpFactory);

    private static ModelSource OfflineSource(
        IReadOnlyList<IInvestigationTool> tools, HttpClient http, PayloadLog payloads,
        InvestigationBudgets budgets) =>
        InvestigationModelFactory.Create(null, tools, http, payloads, budgets);

    [Fact]
    public void KeyStore_MissingTarget_ReturnsNull()
    {
        var store = new CloudKeyStore("Sentinel/Test-" + Guid.NewGuid().ToString("N"));

        Assert.Null(store.ReadKey());
        Assert.False(store.HasKey());
    }

    [Fact]
    public void KeyStore_SaveReadDelete_RoundTrips_OnTestTarget()
    {
        // The ONLY test that writes the vault: unique target, always
        // deleted, never the production entry.
        var store = new CloudKeyStore("Sentinel/Test-" + Guid.NewGuid().ToString("N"));
        try
        {
            store.SaveKey("LLM_TEST_SENTINEL_ROUNDTRIP");
            Assert.True(store.HasKey());
            Assert.Equal("LLM_TEST_SENTINEL_ROUNDTRIP", store.ReadKey());
        }
        finally
        {
            store.DeleteKey();
        }

        Assert.False(store.HasKey());
        store.DeleteKey(); // idempotent: missing entry is success
    }

    [Fact]
    public void Factory_NoKey_YieldsHonestOffline()
    {
        using var http = new HttpClient();
        var source = InvestigationModelFactory.Create(
            null, [], http, new PayloadLog(), new InvestigationBudgets());

        Assert.False(source.IsLive);
        Assert.IsType<OfflineModel>(source.Model);
        Assert.Contains("no cloud key", source.Description);
    }

    [Fact]
    public async Task Factory_Key_YieldsLiveAdapter_OnOfficialEndpoint()
    {
        Assert.Equal(
            "https://api.meta.ai/v1/responses", MetaApiAdapter.DefaultEndpoint);
        string? seenUri = null;
        var handler = new LambdaHandler(req =>
        {
            seenUri = req.RequestUri?.ToString();
            return """{"id":"r","status":"completed","output":[]}""";
        });
        using var http = new HttpClient(handler);
        var source = InvestigationModelFactory.Create(
            "TESTKEY", [], http, new PayloadLog(), new InvestigationBudgets());

        Assert.True(source.IsLive);
        Assert.IsType<MetaApiAdapter>(source.Model);
        var turn = await source.Model.GetNextStepAsync("{\"goal\":\"t\"}", CancellationToken.None);

        Assert.True(turn.Finished);
        Assert.Equal(MetaApiAdapter.DefaultEndpoint, seenUri);
    }

    [Fact]
    public async Task Session_OfflineModel_LeavesLocalResultsStanding()
    {
        var vm = Session(OfflineSource);

        vm.Start(ScanMode.Balanced, _scope);
        Assert.NotNull(vm.RunningTask);
        Assert.NotNull(vm.InvestigatorTask);
        Assert.NotNull(vm.ReconcileTask);
        await vm.RunningTask;
        await vm.InvestigatorTask;
        await vm.ReconcileTask;

        Assert.Equal(ScanSessionState.Completed, vm.State);
        Assert.NotNull(vm.LastResult);
        Assert.Contains("no cloud key", vm.InvestigationLine);
        Assert.Contains("local results stand", vm.InvestigationLine);
        Assert.Empty(vm.ProvisionalFindings);
    }

    [Fact]
    public async Task Session_ScriptedFinding_FlowsToProvisional_AndReconciles()
    {
        var vm = Session((tools, http, payloads, budgets) => new ModelSource(
            new FindingModel(), "test scripted", false));

        vm.Start(ScanMode.Balanced, _scope);
        await vm.RunningTask!;
        await vm.InvestigatorTask!;
        await vm.ReconcileTask!;

        Assert.Equal(ScanSessionState.Completed, vm.State);
        Assert.Contains("1 confirmed", vm.InvestigationLine);
        var line = Assert.Single(vm.ProvisionalFindings);
        Assert.StartsWith("confirmed:", line);
    }

    [Fact]
    public async Task Session_Cancel_StopsInvestigator_AndRecordsIt()
    {
        var model = new BlockingModel();
        var vm = Session((tools, http, payloads, budgets) => new ModelSource(
            model, "test blocking", false));

        vm.Start(ScanMode.Balanced, _scope);
        // Timeouts convert a hang into a located failure, not a
        // wedged suite: the first TimeoutException names the stuck
        // await (this caught a real CanCancel product bug).
        await model.Entered.WaitAsync(TimeSpan.FromSeconds(20));
        await vm.RunningTask!.WaitAsync(TimeSpan.FromSeconds(60));
        Assert.Equal(ScanSessionState.Completed, vm.State);
        Assert.True(vm.CanCancel);
        vm.Cancel();
        await vm.InvestigatorTask!.WaitAsync(TimeSpan.FromSeconds(20));
        await vm.ReconcileTask!.WaitAsync(TimeSpan.FromSeconds(20));

        Assert.Equal("AI: cancelled.", vm.InvestigationLine);
        using var store = new AgentStore(_agentDbPath);
        var inv = Assert.Single(store.ListInvestigations());
        Assert.Equal("Cancelled", inv.Status);
    }

    [Fact]
    public async Task Session_ResumesAbandonedCheckpoint_SameId()
    {
        using (var plant = new AgentStore(_agentDbPath))
        {
            // A11: the abandoned checkpoint carries the scope it was
            // taken under — the session resumes it only because the
            // fingerprint still matches.
            plant.UpsertInvestigation(
                "resume-1", _scope, "Investigate this storage scan.",
                "Investigating", null, 0, 0, 0, 0, 0.0,
                0, 0, 0, 0, 0, false, null, "[]",
                ScopeFingerprint.Compute([_scope], ScanSessionViewModel.DefaultExclusions()));
        }

        var vm = Session(OfflineSource);
        vm.Start(ScanMode.Balanced, _scope);
        await vm.RunningTask!;
        await vm.InvestigatorTask!;
        await vm.ReconcileTask!;

        using var store = new AgentStore(_agentDbPath);
        var inv = Assert.Single(store.ListInvestigations());
        Assert.Equal("resume-1", inv.Id);
        Assert.Equal("Unavailable", inv.Status);
    }

    [Fact]
    public async Task Session_FakeTransportLiveAdapter_RunsEndToEnd()
    {
        var handler = new QueueHandler(
            """
            {"id":"resp_1","status":"completed",
             "output":[{"type":"function_call","name":"get_scan_overview",
             "arguments":"{}","call_id":"call_1"}]}
            """,
            """
            {"id":"resp_2","status":"completed",
             "output":[{"type":"message","role":"assistant",
             "content":[{"type":"output_text","text":"Nothing further."}]}]}
            """);
        var vm = Session(
            (tools, http, payloads, budgets) => new ModelSource(
                new MetaApiAdapter(
                    "TESTKEY-SECRET-999", "https://example.invalid/v1/responses",
                    http, tools, payloads, budgets),
                "test live", true),
            () => new HttpClient(handler));

        vm.Start(ScanMode.Balanced, _scope);
        await vm.RunningTask!;
        await vm.InvestigatorTask!;
        await vm.ReconcileTask!;

        Assert.Equal("AI: done — no findings.", vm.InvestigationLine);
        Assert.NotEmpty(vm.LastPayloads);
        Assert.Contains(vm.LastPayloads, p => p.Kind == "meta-request" && p.Text.Contains("submit_finding"));
        string logged = string.Join("\n", vm.LastPayloads.Select(p => p.Text));
        Assert.DoesNotContain("TESTKEY-SECRET-999", logged);
    }

    private sealed class FindingModel : IInvestigationModel
    {
        public string Name => "finding-test-double";

        private int _turns;
        private bool _emitted;

        public Task<ModelTurn> GetNextStepAsync(string contextJson, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            _turns++;
            string? id = Regex.Matches(contextJson, @"f:\d+")
                .Select(m => m.Value).FirstOrDefault();
            if (id is not null && !_emitted)
            {
                _emitted = true;
                return Task.FromResult(new ModelTurn(null, new FindingDraft(
                    "Saw " + id + " via tool results.",
                    "Test-double interpretation.",
                    [id], string.Empty, string.Empty), false, null));
            }

            if (_emitted || _turns > 100)
            {
                return Task.FromResult(new ModelTurn(null, null, true, "Explored."));
            }

            return Task.FromResult(new ModelTurn(
                new ToolCallRequest("query_inventory", new Dictionary<string, string>
                {
                    ["limit"] = "50",
                }),
                null, false, null));
        }
    }

    private sealed class BlockingModel : IInvestigationModel
    {
        public string Name => "blocking-test-double";

        private readonly TaskCompletionSource _entered = new();

        public Task Entered => _entered.Task;

        public async Task<ModelTurn> GetNextStepAsync(string contextJson, CancellationToken ct)
        {
            _entered.TrySetResult();
            await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);
            throw new OperationCanceledException(ct);
        }
    }

    private sealed class LambdaHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, string> _respond;

        public LambdaHandler(Func<HttpRequestMessage, string> respond)
        {
            _respond = respond;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(_respond(request)),
            });
        }
    }

    private sealed class QueueHandler : HttpMessageHandler
    {
        private readonly Queue<string> _responses;

        public QueueHandler(params string[] responses)
        {
            _responses = new Queue<string>(responses);
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(_responses.Dequeue()),
            });
        }
    }
}
