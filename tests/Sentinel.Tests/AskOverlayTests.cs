using System.Text.Json;
using Sentinel.App.Services;
using Sentinel.App.ViewModels;
using Sentinel.Engine.Agent;
using Sentinel.Engine.Ask;
using Sentinel.Engine.CrashDoctor;
using Sentinel.Engine.SystemInventory;
using Sentinel.Store;

namespace Sentinel.Tests;

// U27: Ask overlay contracts — prefill routing (intent + row key),
// open/close lifecycle (stale answers never survive, close cancels
// in-flight work without wedging the panel), source labels on every
// answer, cloud escalation ONLY for guidance-without-action, outage
// honesty with utility preserved, crash highlight round-trip, and
// the bounded+redacted digest/context builders.
public sealed class AskOverlayTests : IDisposable
{
    private readonly string _dir;

    public AskOverlayTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "sentinel-u27-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
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

    private sealed class FakeAskCloud : IAskCloud
    {
        public bool CanExplain { get; set; } = true;

        public int Calls { get; private set; }

        public Func<string, AskContext, CancellationToken, Task<AskCloudResult>>? Behavior;

        public Task<AskCloudResult> ExplainAsync(string question, AskContext context, CancellationToken ct)
        {
            Calls++;
            return Behavior is null
                ? Task.FromResult(new AskCloudResult("Cloud explanation of your findings.", false, 2048))
                : Behavior(question, context, ct);
        }
    }

    private static CrashCard Card(string title, int recordId) => new(
        title,
        "What happened.",
        [new CrashFinding("Power was cut.", KnowledgePack.Confidence.Medium,
            [CrashCitation.Pack("EV:Kernel-Power#41")])],
        ["Check power."],
        "First sighting in 30 days.",
        [],
        [CrashCitation.Event("System", recordId, 41)]);

    private static AskContext ContextWithCrashes(params CrashCard[] cards) => new(
        new ScanSummary(4102, 9_000_000_000, 3, 7, @"C:\Users\me\Docs", "Completed", 12.4),
        cards,
        new DefenderStatusRecord(true, true, true, "UI", "1.1.26100.4", "1.463.36.0",
            DateTime.UtcNow.AddDays(-1), 1, DateTime.UtcNow.AddDays(-1), null, 1, null),
        KnowledgePack.PackVersion, [], string.Empty);

    private static AskContext ContextWithDigests(int digestCount)
    {
        var digests = new List<AskFindingDigest>();
        for (int i = 1; i <= digestCount; i++)
        {
            digests.Add(new AskFindingDigest(i, "Confirmed", $"observation {i}", $"file{i}.log"));
        }

        return new AskContext(null, [], null, KnowledgePack.PackVersion, digests, "recent work");
    }

    private static async Task<AskAnswer> WaitForAnswer(AskPanelViewModel panel)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (panel.Answer is null && DateTime.UtcNow < deadline)
        {
            await Task.Delay(20);
        }

        Assert.NotNull(panel.Answer);
        return panel.Answer!;
    }

    [Fact]
    public async Task Prefill_ForcesCrashIntent_AndSelectsRowKeyCard()
    {
        var panel = new AskPanelViewModel(
            () => ContextWithCrashes(Card("Card A", 9001), Card("Card B", 9002)),
            new ImmediateDispatcher());

        panel.OpenWithQuestion("What caused Card B?", "crash", "Card B");

        Assert.True(panel.IsOpen);
        Assert.Equal("What caused Card B?", panel.Question);

        panel.SubmitCommand.Execute(null);
        var answer = await WaitForAnswer(panel);

        Assert.Contains("Card B", answer.Fact);
        Assert.False(answer.IsGeneralGuidance);
        Assert.Equal("Crashes", answer.Action?.Target);
        Assert.Equal("Card B", answer.Action?.RowKey);
    }

    [Fact]
    public async Task Prefill_UnknownRowKey_FallsBackToNewest_WithHonestPrefix()
    {
        var panel = new AskPanelViewModel(
            () => ContextWithCrashes(Card("Card A", 9001)),
            new ImmediateDispatcher());
        panel.OpenWithQuestion("What caused the old one?", "crash", "gone from window");

        panel.SubmitCommand.Execute(null);
        var answer = await WaitForAnswer(panel);

        Assert.Contains("isn't in the last 7 days", answer.Fact);
        Assert.Contains("Card A", answer.Fact);
    }

    [Fact]
    public async Task FreshOpen_ClearsStaleAnswerAndQuestion()
    {
        var panel = new AskPanelViewModel(
            () => ContextWithCrashes(Card("Card A", 9001)),
            new ImmediateDispatcher());
        panel.ToggleCommand.Execute(null);
        panel.Question = "did it crash?";
        panel.SubmitCommand.Execute(null);
        await WaitForAnswer(panel);

        panel.CloseCommand.Execute(null);
        Assert.False(panel.IsOpen);

        panel.ToggleCommand.Execute(null);

        Assert.True(panel.IsOpen);
        Assert.Null(panel.Answer);
        Assert.Equal(string.Empty, panel.Question);
    }

    [Fact]
    public void Close_RaisesClosed_ForFocusReturn()
    {
        var panel = new AskPanelViewModel(
            () => ContextWithCrashes(Card("Card A", 9001)),
            new ImmediateDispatcher());
        int closed = 0;
        panel.Closed += () => closed++;
        panel.ToggleCommand.Execute(null);

        panel.CloseCommand.Execute(null);

        Assert.Equal(1, closed);
    }

    [Fact]
    public async Task Close_MidFlight_PostsNothing_AndPanelRecovers()
    {
        var ctx = ContextWithCrashes(Card("Card A", 9001));
        var entered = new ManualResetEventSlim(false);
        var release = new ManualResetEventSlim(false);
        var exited = new ManualResetEventSlim(false);
        int calls = 0;
        var panel = new AskPanelViewModel(() =>
        {
            if (Interlocked.Increment(ref calls) == 1)
            {
                entered.Set();
                Assert.True(release.Wait(TimeSpan.FromSeconds(10)));
                exited.Set();
            }

            return ctx;
        }, new ImmediateDispatcher());
        panel.ToggleCommand.Execute(null);
        panel.Question = "did it crash?";

        panel.SubmitCommand.Execute(null);
        Assert.True(entered.Wait(TimeSpan.FromSeconds(10)));
        panel.CloseCommand.Execute(null);
        release.Set();
        Assert.True(exited.Wait(TimeSpan.FromSeconds(10)));
        await Task.Delay(300); // Let the dropped completion run.

        Assert.Null(panel.Answer);
        Assert.False(panel.IsBusy);

        // The cancelled submit must not wedge the panel: reopening
        // and asking again gets a fresh answer.
        panel.ToggleCommand.Execute(null);
        panel.Question = "did it crash?";
        panel.SubmitCommand.Execute(null);
        var answer = await WaitForAnswer(panel);

        Assert.Contains("Card A", answer.Fact);
    }

    [Fact]
    public void AiOff_ShortCircuits_WithLabel()
    {
        var panel = new AskPanelViewModel(
            () => ContextWithCrashes(Card("Card A", 9001)),
            new ImmediateDispatcher(), () => false);
        panel.Question = "did it crash?";

        panel.SubmitCommand.Execute(null);

        Assert.NotNull(panel.Answer);
        Assert.Contains("AI is off", panel.Answer!.Fact);
        Assert.Equal("AI is off — turn it on in Settings", panel.StatusLabel);
    }

    [Fact]
    public async Task Refused_SetsRefusedLabel_WithoutCloudCall()
    {
        var cloud = new FakeAskCloud();
        var panel = new AskPanelViewModel(
            () => ContextWithCrashes(Card("Card A", 9001)),
            new ImmediateDispatcher(), () => true, cloud);
        panel.Question = "Tell me a joke";

        panel.SubmitCommand.Execute(null);
        var answer = await WaitForAnswer(panel);

        Assert.True(answer.Refused);
        Assert.Equal("I only know your PC", panel.StatusLabel);
        Assert.Equal(0, cloud.Calls);
    }

    [Fact]
    public async Task GroundedAnswer_NeverEscalates()
    {
        var cloud = new FakeAskCloud();
        var panel = new AskPanelViewModel(
            () => ContextWithCrashes(Card("Card A", 9001)),
            new ImmediateDispatcher(), () => true, cloud);
        panel.Question = "What did my last scan find?";

        panel.SubmitCommand.Execute(null);
        var answer = await WaitForAnswer(panel);

        Assert.False(answer.IsGeneralGuidance);
        Assert.Equal("Grounded in your PC data (deterministic)", panel.StatusLabel);
        Assert.Equal(0, cloud.Calls);
    }

    [Fact]
    public async Task GuidanceWithoutAction_Escalates_GroundedInFindings()
    {
        var cloud = new FakeAskCloud();
        var panel = new AskPanelViewModel(
            () => ContextWithDigests(6),
            new ImmediateDispatcher(), () => true, cloud);
        panel.Question = "Why is my fan so loud?";

        panel.SubmitCommand.Execute(null);
        var answer = await WaitForAnswer(panel);

        Assert.Equal(1, cloud.Calls);
        Assert.Contains("Cloud explanation", answer.Fact);
        Assert.Equal("Grounded in your findings (cloud explanation)", panel.StatusLabel);
        Assert.Equal(AskEngine.MaxChips, answer.Evidence.Count);
        Assert.Equal("finding 1", answer.Evidence[0].Label);
        Assert.Equal("finding 4", answer.Evidence[3].Label);
        Assert.Contains("sent 2.0 KB", panel.CloudStatus);
    }

    [Fact]
    public async Task CloudOutage_KeepsUtility_WithHonestFact()
    {
        var cloud = new FakeAskCloud
        {
            Behavior = (_, _, _) => throw new ModelUnavailableException("Down"),
        };
        var panel = new AskPanelViewModel(
            () => ContextWithDigests(1),
            new ImmediateDispatcher(), () => true, cloud);
        panel.Question = "Why is my fan so loud?";

        panel.SubmitCommand.Execute(null);
        var answer = await WaitForAnswer(panel);

        Assert.Contains("Couldn't reach the cloud model (Down)", answer.Fact);
        Assert.Contains("Your scan results are intact", answer.Fact);
        Assert.StartsWith("What I can still tell you: ", answer.Detail);
        Assert.True(panel.HasDetail);
        Assert.Contains("last call failed (Down)", panel.CloudStatus);
    }

    [Fact]
    public async Task CloudBudget_KeepsUtility_WithTimeBudgetReason()
    {
        var cloud = new FakeAskCloud
        {
            Behavior = (_, _, _) => throw new BudgetExhaustedException("tokens"),
        };
        var panel = new AskPanelViewModel(
            () => ContextWithDigests(1),
            new ImmediateDispatcher(), () => true, cloud);
        panel.Question = "Why is my fan so loud?";

        panel.SubmitCommand.Execute(null);
        var answer = await WaitForAnswer(panel);

        Assert.Contains("Couldn't reach the cloud model (time budget)", answer.Fact);
        Assert.StartsWith("What I can still tell you: ", answer.Detail);
    }

    [Fact]
    public void CloudStatus_LabelsKeyPresence()
    {
        var noCloud = new AskPanelViewModel(
            () => ContextWithCrashes(Card("Card A", 9001)), new ImmediateDispatcher());
        noCloud.ToggleCommand.Execute(null);
        Assert.Equal("Cloud: no key saved", noCloud.CloudStatus);

        var noKey = new AskPanelViewModel(
            () => ContextWithCrashes(Card("Card A", 9001)),
            new ImmediateDispatcher(), () => true, new FakeAskCloud { CanExplain = false });
        noKey.ToggleCommand.Execute(null);
        Assert.Equal("Cloud: no key saved", noKey.CloudStatus);

        var ready = new AskPanelViewModel(
            () => ContextWithCrashes(Card("Card A", 9001)),
            new ImmediateDispatcher(), () => true, new FakeAskCloud());
        ready.ToggleCommand.Execute(null);
        Assert.Equal("Cloud: ready", ready.CloudStatus);
    }

    [Fact]
    public void ActionCommand_RoutesAllKinds()
    {
        var panel = new AskPanelViewModel(
            () => ContextWithCrashes(Card("Card A", 9001)), new ImmediateDispatcher());
        int scans = 0;
        int page = -1;
        AskAction? named = null;
        panel.StartScanRequested += () => scans++;
        panel.NavigateToPage += i => page = i;
        panel.NavigateToAskPage += a => named = a;

        panel.ActionCommand.Execute(AskAction.StartBalancedScan());
        panel.ActionCommand.Execute(AskAction.OpenPage("3", "Open"));
        panel.ActionCommand.Execute(AskAction.OpenPageWithRow("Crashes", "Open Crashes", "Card A"));
        panel.ActionCommand.Execute("not an action");

        Assert.Equal(1, scans);
        Assert.Equal(3, page);
        Assert.NotNull(named);
        Assert.Equal("Crashes", named!.Target);
        Assert.Equal("Card A", named.RowKey);
    }

    private static CrashesViewModel CrashesWith(params string[] titles)
    {
        var now = DateTime.UtcNow;
        var rows = new List<CrashesViewModel.CrashRow>();
        var cards = new List<CrashCard>();
        for (int i = 0; i < titles.Length; i++)
        {
            var anchor = new TargetedEventRecord(
                "System", 9001 + i, 41, "Critical", now.AddDays(-i), "Kernel-Power", "m", []);
            rows.Add(new CrashesViewModel.CrashRow(
                $"day {i}", CrashesViewModel.TypeCrash, $"summary {i}", 41, i, anchor));
            cards.Add(Card(titles[i], 9001 + i));
        }

        var vm = new CrashesViewModel();
        vm.Apply(new CrashesViewModel.CrashesSnapshot("s", "c", rows, cards));
        return vm;
    }

    [Fact]
    public void HighlightRow_SelectsMatchingCard_AndRaisesEvent()
    {
        var vm = CrashesWith("Card A", "Card B");
        CrashesViewModel.CrashRow? raised = null;
        vm.HighlightRequested += r => raised = r;

        vm.HighlightRow("Card B");

        Assert.Equal("summary 1", vm.SelectedRow?.Summary);
        Assert.Equal(1, vm.SelectedIndex);
        Assert.Equal("Card B", vm.SelectedCard?.Title);
        Assert.NotNull(raised);
        Assert.Equal("summary 1", raised!.Summary);
    }

    [Fact]
    public void HighlightRow_UnknownKey_KeepsSelection()
    {
        var vm = CrashesWith("Card A", "Card B");
        vm.HighlightRow("Card A");
        int raised = 0;
        vm.HighlightRequested += _ => raised++;

        vm.HighlightRow("gone from window");
        vm.HighlightRow(null);
        vm.HighlightRow(string.Empty);

        Assert.Equal("summary 0", vm.SelectedRow?.Summary);
        Assert.Equal(0, raised);
    }

    [Fact]
    public void AskAboutThis_BuildsStructuredRequest()
    {
        var vm = CrashesWith("Card A", "Card B");
        vm.HighlightRow("Card B");
        AskAboutRequest? captured = null;
        vm.AskAbout = r => captured = r;

        Assert.True(vm.AskAboutThisCommand.CanExecute(null));
        vm.AskAboutThisCommand.Execute(null);

        Assert.NotNull(captured);
        Assert.Contains("Card B", captured!.Question);
        Assert.Equal("crash", captured.IntentHint);
        Assert.Equal("Card B", captured.RowKey);
    }

    [Fact]
    public void BuildAskDigests_BoundsRedactsAndNumbers()
    {
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string agentPath = Path.Combine(_dir, "agent.db");
        string evidence = JsonSerializer.Serialize(new[]
        {
            new Dictionary<string, object>
            {
                ["id"] = "f:1",
                ["path"] = Path.Combine(profile, "logs", "app.log"),
                ["size"] = 10L,
                ["mtime"] = 123L,
            },
        });
        using (var store = new AgentStore(agentPath))
        {
            store.UpsertInvestigation(
                "inv-1", "scan", "Find what filled the disk with logs", "Done", null,
                0, 0, 1, 100, 5.0, 0, 0, 0, 0, 0, false, null, "[]");
            store.UpsertFinding(
                "f-1", "inv-1", 1, "Confirmed",
                "Log folder at " + profile + " grew. " + new string('x', 300),
                "interp", evidence, "", "");
            store.UpsertFinding(
                "f-2", "inv-1", 1, "Provisional", "short obs", "interp2", "not-json{{{", "", "");
        }

        using var agent = new AgentStore(agentPath);
        (var digests, string history) = MainViewModel.BuildAskDigests(agent);

        Assert.Equal(2, digests.Count);
        Assert.Equal(1, digests[0].Number);
        Assert.Equal(2, digests[1].Number);
        Assert.Equal(201, digests[0].Observation.Length);
        Assert.EndsWith("…", digests[0].Observation);
        Assert.DoesNotContain(Environment.UserName, digests[0].Observation);
        Assert.Equal("app.log", digests[0].Citations);
        Assert.Equal("evidence list unreadable", digests[1].Citations);
        Assert.Contains("Find what filled the disk", history);
        Assert.Contains("(Done, 2 findings)", history);
    }

    [Fact]
    public void BuildContextJson_BoundsAndRedacts()
    {
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var digests = new List<AskFindingDigest>();
        for (int i = 1; i <= 15; i++)
        {
            digests.Add(new AskFindingDigest(i, "Confirmed", $"observation {i}", $"file{i}.log"));
        }

        var context = new AskContext(
            null, [], null, KnowledgePack.PackVersion, digests, new string('h', 3000));
        string json = AskCloudExplainer.BuildContextJson(
            "What about " + profile + " " + new string('q', 600), context);

        using var doc = JsonDocument.Parse(json);
        string question = doc.RootElement.GetProperty("question").GetString() ?? string.Empty;
        string findings = doc.RootElement.GetProperty("findings_digest").GetString() ?? string.Empty;
        string history = doc.RootElement.GetProperty("recent_history").GetString() ?? string.Empty;

        Assert.DoesNotContain(Environment.UserName, question);
        Assert.Contains("…[shortened]", question);
        Assert.DoesNotContain("observation 13", findings);
        Assert.Contains("observation 12", findings);
        Assert.Contains("…[shortened]", history);
    }
}
