using System.Net.Http;
using System.Text;
using Sentinel.App.Services;
using Sentinel.App.ViewModels;
using Sentinel.Engine.Agent;
using Sentinel.Engine.Scan;
using Sentinel.Store;

namespace Sentinel.Tests;

// A05: the actual sent payload is inspectable — last actual
// request shown, bounded history navigable (including entries
// past the fifth), per-entry destination/class/time/bytes/
// redaction/truncation, explicit capacity accounting, and no
// credential material in UI or persisted logs.
public sealed class PayloadInspectorTests : IDisposable
{
    private readonly string _dir;
    private readonly string _settingsPath;
    private readonly string _dbPath;
    private readonly string _agentDbPath;

    public PayloadInspectorTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "sentinel-a05-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _settingsPath = Path.Combine(_dir, "settings.json");
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

    private SettingsViewModel Settings() =>
        new(new SettingsStore(_settingsPath),
            () => new SentinelDb(_dbPath), () => new AgentStore(_agentDbPath),
            () => _dir);

    // A05: a request cannot silently outlive capture capacity.
    // The log is a ring: oldest evicted, eviction counted, and
    // sequence numbers stay ordered so gaps are visible.
    [Fact]
    public void Ring_EvictsOldest_CountsEvictions_SequencesStayOrdered()
    {
        var log = new PayloadLog();
        for (int i = 1; i <= PayloadLog.MaxEntries + 3; i++)
        {
            log.Append("k", "entry-" + i);
        }

        var entries = log.Entries;
        Assert.Equal(PayloadLog.MaxEntries, entries.Count);
        Assert.Equal(3, log.Evicted);
        Assert.Equal(PayloadLog.MaxEntries + 3, log.TotalAppended);
        Assert.Equal("entry-4", entries[0].Text);
        Assert.Equal(4, entries[0].Seq);
        Assert.Equal(PayloadLog.MaxEntries + 3, entries[^1].Seq);
        // Ordered, gap-free within the retained window.
        for (int i = 1; i < entries.Count; i++)
        {
            Assert.Equal(entries[i - 1].Seq + 1, entries[i].Seq);
        }

        var snapshot = log.Snapshot();
        Assert.Equal(3, snapshot.Evicted);
        Assert.Equal(PayloadLog.MaxEntries + 3, snapshot.TotalAppended);
        Assert.Equal(PayloadLog.MaxEntries, snapshot.MaxEntries);
    }

    [Fact]
    public void Append_Records_Destination_Class_Redaction_Truncation()
    {
        var log = new PayloadLog();
        log.Append("meta-request", "{}", "api.meta.ai", "C+F", redacted: true, truncated: false);

        var entry = Assert.Single(log.Entries);
        Assert.Equal(1, entry.Seq);
        Assert.Equal("api.meta.ai", entry.Destination);
        Assert.Equal("C+F", entry.DataClass);
        Assert.True(entry.Redacted);
        Assert.False(entry.Truncated);
    }

    [Fact]
    public void Stages_Distinguish_Preview_Attempt_Response_Outcome()
    {
        Assert.Equal("Preview", PayloadStages.Label("model-request"));
        Assert.Equal("Attempted send", PayloadStages.Label("meta-request"));
        Assert.Equal("Response", PayloadStages.Label("model-response"));
        Assert.Equal("Response", PayloadStages.Label("meta-response"));
        Assert.Equal("Send failed", PayloadStages.Label("meta-error"));
        Assert.Equal("Send cancelled", PayloadStages.Label("meta-cancelled"));
    }

    [Fact]
    public async Task MetaAdapter_TransportFailure_Appends_ErrorMarker_NoKey()
    {
        var payloads = new PayloadLog();
        var adapter = new MetaApiAdapter(
            "TESTKEY-A05-TRANSPORT", "https://example.invalid/v1/responses",
            new HttpClient(new ThrowingHandler()), TestTools(payloads),
            payloads, new InvestigationBudgets());

        var ex = await Assert.ThrowsAsync<ModelUnavailableException>(
            () => adapter.GetNextStepAsync("{\"goal\":\"t\"}", CancellationToken.None));

        Assert.StartsWith("Transport:", ex.Message);
        Assert.Contains(payloads.Entries, e => e.Kind == "meta-error");
        string logged = string.Join("\n", payloads.Entries.Select(e => e.Text));
        Assert.DoesNotContain("TESTKEY-A05-TRANSPORT", logged);
    }

    [Fact]
    public async Task MetaAdapter_Cancel_Appends_CancelMarker()
    {
        var payloads = new PayloadLog();
        var adapter = new MetaApiAdapter(
            "TESTKEY-A05-CANCEL", "https://example.invalid/v1/responses",
            new HttpClient(new ThrowingHandler(new OperationCanceledException())),
            TestTools(payloads), payloads, new InvestigationBudgets());

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => adapter.GetNextStepAsync("{\"goal\":\"t\"}", CancellationToken.None));

        Assert.Contains(payloads.Entries, e => e.Kind == "meta-cancelled");
        string logged = string.Join("\n", payloads.Entries.Select(e => e.Text));
        Assert.DoesNotContain("TESTKEY-A05-CANCEL", logged);
    }

    [Fact]
    public async Task MetaAdapter_HttpError_Appends_Response_Then_ErrorMarker()
    {
        var payloads = new PayloadLog();
        var adapter = new MetaApiAdapter(
            "TESTKEY-A05-HTTP", "https://example.invalid/v1/responses",
            new HttpClient(new StatusHandler(500, "{\"error\":\"boom\"}")),
            TestTools(payloads), payloads, new InvestigationBudgets());

        var ex = await Assert.ThrowsAsync<ModelUnavailableException>(
            () => adapter.GetNextStepAsync("{\"goal\":\"t\"}", CancellationToken.None));

        Assert.Equal("Http500", ex.Message);
        Assert.Contains(payloads.Entries, e => e.Kind == "meta-response");
        var marker = Assert.Single(payloads.Entries, e => e.Kind == "meta-error");
        Assert.Contains("Http500", marker.Text);
        string logged = string.Join("\n", payloads.Entries.Select(e => e.Text));
        Assert.DoesNotContain("TESTKEY-A05-HTTP", logged);
    }

    [Fact]
    public async Task MetaRequest_Destination_Is_Host_Only()
    {
        var payloads = new PayloadLog();
        var adapter = new MetaApiAdapter(
            "TESTKEY-A05-HOST", "https://example.invalid/v1/responses?ignored=1",
            new HttpClient(new StatusHandler(200, """{"status":"completed","output":[]}""")),
            TestTools(payloads), payloads, new InvestigationBudgets());

        // Runs through the fake transport; the attempted-send entry
        // records the peer host, never a query string.
        _ = await adapter.GetNextStepAsync("{\"goal\":\"t\"}", CancellationToken.None);

        var sent = Assert.Single(payloads.Entries, e => e.Kind == "meta-request");
        Assert.Equal("example.invalid", sent.Destination);
        Assert.Equal("C+F", sent.DataClass);
        Assert.True(sent.Redacted);
    }

    // A05: the last ACTUAL request is shown by default, and every
    // retained entry — including ones past the fifth — is reachable.
    [Fact]
    public void Inspector_Shows_Last_Request_By_Default_And_Navigates_To_Oldest()
    {
        var log = new PayloadLog();
        for (int i = 1; i <= 8; i++)
        {
            log.Append("meta-request", "synthetic-request-" + i + "-end",
                "api.meta.ai", "C+F", redacted: true, truncated: false);
        }

        var vm = Settings();
        vm.PayloadHistoryProvider = () => log.Snapshot();
        vm.ShowPayloadsCommand.Execute(null);

        Assert.Equal(8, vm.PayloadRows.Count);
        Assert.NotNull(vm.SelectedPayloadRow);
        Assert.Equal(8, vm.SelectedPayloadRow.Entry.Seq);
        Assert.Contains("synthetic-request-8-end", vm.PayloadDetail);
        Assert.Contains("synthetic-request-8-end", vm.PayloadPreview);
        // Per-entry metadata is on the detail surface.
        Assert.Contains("api.meta.ai", vm.PayloadDetail);
        Assert.Contains("C+F", vm.PayloadDetail);
        Assert.Contains("UTF-8 bytes", vm.PayloadDetail);
        Assert.Contains("redacted", vm.PayloadDetail);
        Assert.Contains("truncated", vm.PayloadDetail);

        // Navigate past the fifth entry to the oldest one.
        vm.SelectedPayloadRow = vm.PayloadRows[0];
        Assert.Contains("synthetic-request-1-end", vm.PayloadDetail);
    }

    [Fact]
    public void Inspector_Capacity_Line_States_Evictions_Explicitly()
    {
        var log = new PayloadLog();
        for (int i = 1; i <= PayloadLog.MaxEntries + 2; i++)
        {
            log.Append("k", "e" + i);
        }

        var vm = Settings();
        vm.PayloadHistoryProvider = () => log.Snapshot();
        vm.ShowPayloadsCommand.Execute(null);

        Assert.Contains("evicted", vm.PayloadCapacityLine);
        Assert.Contains("2", vm.PayloadCapacityLine);
        Assert.DoesNotContain("evicted", Settings().PayloadCapacityLine);
    }

    // A05: no credential headers/keys in UI or persisted logs.
    [Fact]
    public async Task Inspector_Surfaces_No_Key_Material_Ui_Or_Persisted()
    {
        const string key = "TESTKEY-A05-NOKEY-777";
        string scope = Path.Combine(_dir, "scope");
        Directory.CreateDirectory(scope);
        File.WriteAllText(Path.Combine(scope, "a.txt"), "alpha");
        var handler = new QueueHandler(
            """
            {"id":"resp_1","status":"completed",
             "output":[{"type":"message","role":"assistant",
             "content":[{"type":"output_text","text":"Nothing further."}]}]}
            """);
        var session = new ScanSessionViewModel(
            () => new SentinelDb(_dbPath), null, new ImmediateDispatcher(),
            () => new AgentStore(_agentDbPath), () => true,
            (tools, http, payloads, budgets) => new ModelSource(
                new MetaApiAdapter(
                    key, "https://example.invalid/v1/responses",
                    http, tools, payloads, budgets),
                "test live", true),
            () => new HttpClient(handler));
        session.Start(ScanMode.Balanced, scope);
        await session.RunningTask!;
        await session.InvestigatorTask!;
        await session.ReconcileTask!;

        Assert.NotEmpty(session.LastPayloads);
        var vm = Settings();
        vm.PayloadHistoryProvider = () => new PayloadHistorySnapshot(
            session.LastPayloads, 0, session.LastPayloads.Count, PayloadLog.MaxEntries);
        vm.ShowPayloadsCommand.Execute(null);

        string ui = vm.PayloadPreview + "\n" + vm.PayloadDetail + "\n" +
            vm.PayloadCapacityLine + "\n" +
            string.Join("\n", vm.PayloadRows.Select(r => r.Summary));
        Assert.DoesNotContain(key, ui);
        Assert.DoesNotContain("Bearer", ui);
        Assert.DoesNotContain("Authorization", ui);

        // Persisted surfaces: audit exports + settings file + DBs.
        var history = new HistoryViewModel(
            () => new SentinelDb(_dbPath), () => new AgentStore(_agentDbPath));
        string persisted = history.BuildAuditJson() + "\n" + history.BuildAuditHtml();
        if (File.Exists(_settingsPath))
        {
            persisted += "\n" + File.ReadAllText(_settingsPath);
        }

        persisted += "\n" + ReadDbText(_dbPath) + "\n" + ReadDbText(_agentDbPath);
        Assert.DoesNotContain(key, persisted);
        Assert.DoesNotContain("Bearer " + key, persisted);
    }

    private static List<IInvestigationTool> TestTools(PayloadLog payloads)
    {
        var hub = new EvidencePreviewHub();
        return new List<IInvestigationTool>(new StorageTools(hub).All)
        {
            new ExcerptTools(hub),
            new EventTools(hub),
        };
    }

    private static string ReadDbText(string path)
    {
        if (!File.Exists(path))
        {
            return string.Empty;
        }

        // Raw bytes as Latin-1: any stored key material shows up
        // regardless of SQLite framing. Shared read: a pooled
        // connection may still hold the file.
        using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        using var sink = new MemoryStream();
        stream.CopyTo(sink);
        return Encoding.Latin1.GetString(sink.ToArray());
    }

    private sealed class ThrowingHandler : HttpMessageHandler
    {
        private readonly Exception _error;

        public ThrowingHandler(Exception? error = null) =>
            _error = error ?? new HttpRequestException("simulated outage");

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct) => throw _error;
    }

    private sealed class StatusHandler : HttpMessageHandler
    {
        private readonly int _status;
        private readonly string _body;

        public StatusHandler(int status, string body)
        {
            _status = status;
            _body = body;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage((System.Net.HttpStatusCode)_status)
            {
                Content = new StringContent(_body),
            });
    }

    private sealed class QueueHandler : HttpMessageHandler
    {
        private readonly Queue<string> _bodies;

        public QueueHandler(params string[] bodies) => _bodies = new Queue<string>(bodies);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            string body = _bodies.Count > 0 ? _bodies.Dequeue() : """{"status":"completed","output":[]}""";
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(body),
            });
        }
    }
}
