using Sentinel.App.Services;
using Sentinel.App.ViewModels;
using Sentinel.Engine.Ask;
using Sentinel.Engine.CrashDoctor;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.Tests;

// Panel grounding tests (04): answers come ONLY from the context,
// render one fact + evidence + at most one action, label unlinked
// text "general guidance", refuse off-topic, and respect caps.
public sealed class AskPanelTests
{
    private static AskContext FullContext() => new(
        new ScanSummary(4102, 9_000_000_000, 3, 7, @"C:\Users\me\Docs", "Completed", 12.4),
        [
            new CrashCard(
                "Unexpected shutdown (Event 41)",
                "What happened.",
                [new CrashFinding("Power was cut.", KnowledgePack.Confidence.Medium,
                    [CrashCitation.Pack("EV:Kernel-Power#41")])],
                ["Check power."],
                "First sighting in 30 days.",
                [],
                [CrashCitation.Event("System", 9001, 41)]),
        ],
        new DefenderStatusRecord(true, true, true, "UI", "1.1.26100.4", "1.463.36.0",
            DateTime.UtcNow.AddDays(-1), 1, DateTime.UtcNow.AddDays(-1), null, 1, null),
        KnowledgePack.PackVersion, [], string.Empty);

    private static AskContext EmptyContext() => new(null, [], null, KnowledgePack.PackVersion, [], string.Empty);

    [Fact]
    public void LastScan_Answers_FromScanSummary()
    {
        var answer = AskEngine.Answer("What did my last scan find?", FullContext());

        Assert.False(answer.Refused);
        Assert.False(answer.IsGeneralGuidance);
        Assert.Contains("4102", answer.Fact);
        Assert.Contains(answer.Evidence, c => c.Label == "generation");
        Assert.NotNull(answer.Action);
        Assert.Equal("OpenPage", answer.Action!.Kind);
    }

    [Fact]
    public void Storage_Answers_WithBytes_And_OneAction()
    {
        var answer = AskEngine.Answer("What is eating my disk?", FullContext());

        Assert.Contains("8.4 GB", answer.Fact);
        Assert.Equal("Storage", answer.Action?.Target);
    }

    [Fact]
    public void Crash_And_Threat_Actions_OpenTheirPages()
    {
        Assert.Equal("Crashes", AskEngine.Answer("did it crash?", FullContext()).Action?.Target);
        Assert.Equal("Threats", AskEngine.Answer("am I protected?", FullContext()).Action?.Target);
        Assert.Equal("Storage", AskEngine.Answer("last scan?", FullContext()).Action?.Target);
    }

    [Fact]
    public void Crash_Answers_FromNewestCard_WithCitations()
    {
        var answer = AskEngine.Answer("Did that crash happen before?", FullContext());

        Assert.Contains("Unexpected shutdown", answer.Fact);
        Assert.Contains(answer.Evidence, c => c.Detail == "EV:Kernel-Power#41");
        Assert.Contains(answer.Evidence, c => c.Detail == "System#9001");
    }

    [Fact]
    public void Crash_WithNoCrashes_SaysSo_WithEvidence()
    {
        var answer = AskEngine.Answer("did my pc crash?", EmptyContext());

        Assert.False(answer.Refused);
        Assert.Contains("No crashes", answer.Fact);
        Assert.NotEmpty(answer.Evidence);
    }

    [Fact]
    public void Threat_Answers_FromDefenderStatus()
    {
        var answer = AskEngine.Answer("Is my PC protected?", FullContext());

        Assert.Contains("Real-time protection is on", answer.Fact);
        Assert.Contains(answer.Evidence, c => c.Label == "engine");
    }

    [Fact]
    public void FileSpecific_WithoutFile_IsGeneralGuidance()
    {
        var answer = AskEngine.Answer("Is this file safe?", FullContext());

        Assert.False(answer.Refused);
        Assert.True(answer.IsGeneralGuidance);
        Assert.Empty(answer.Evidence);
    }

    [Fact]
    public void StartScan_Returns_ScanAction()
    {
        var answer = AskEngine.Answer("Start a Balanced scan", FullContext());

        Assert.Equal("StartBalancedScan", answer.Action?.Kind);
    }

    [Fact]
    public void MissingData_Yields_Guidance_WithNextStep()
    {
        var answer = AskEngine.Answer("What did my last scan find?", EmptyContext());

        Assert.True(answer.IsGeneralGuidance);
        Assert.Equal("StartBalancedScan", answer.Action?.Kind);
    }

    [Fact]
    public void OffTopic_IsRefused()
    {
        foreach (string q in new[] { "Tell me a joke", "Weather today?", "What is the capital of France?" })
        {
            var answer = AskEngine.Answer(q, FullContext());
            Assert.True(answer.Refused, q);
            Assert.Null(answer.Action);
            Assert.Empty(answer.Evidence);
        }
    }

    [Fact]
    public void UnknownPcTopic_IsGeneralGuidance_NotRefusal()
    {
        var answer = AskEngine.Answer("Why is my fan so loud?", FullContext());

        Assert.False(answer.Refused);
        Assert.True(answer.IsGeneralGuidance);
    }

    [Fact]
    public void Caps_FactChips_And_AtMostOneAction()
    {
        var longCrash = new CrashCard(
            "t",
            "w",
            [new CrashFinding(new string('x', 2000), KnowledgePack.Confidence.Low,
                [CrashCitation.Pack("K")])],
            [], "trend", [],
            [CrashCitation.Event("System", 1, 41), CrashCitation.Event("System", 2, 41),
             CrashCitation.Event("System", 3, 41), CrashCitation.Event("System", 4, 41),
             CrashCitation.Event("System", 5, 41)]);
        var context = FullContext() with { RecentCrashes = new[] { longCrash } };

        var answer = AskEngine.Answer("crash?", context);

        Assert.True(answer.Fact.Length <= AskEngine.MaxFactChars, $"fact is {answer.Fact.Length} chars");
        Assert.True(answer.Evidence.Count <= AskEngine.MaxChips, $"chips: {answer.Evidence.Count}");
    }

    [Fact]
    public void SuggestedChips_AllWork_WithEmptyContext()
    {
        Assert.Equal(4, AskEngine.SuggestedChips.Count);
        foreach (string chip in AskEngine.SuggestedChips)
        {
            var answer = AskEngine.Answer(chip, EmptyContext());
            Assert.False(answer.Refused, chip);
            Assert.False(string.IsNullOrWhiteSpace(answer.Fact), chip);
        }
    }

    [Fact]
    public void Panel_Toggle_Opens_And_ClearsQuestion()
    {
        var panel = new AskPanelViewModel(EmptyContext, new ImmediateDispatcher());
        panel.Question = "stale";

        panel.ToggleCommand.Execute(null);

        Assert.True(panel.IsOpen);
        Assert.Equal(string.Empty, panel.Question);

        panel.CloseCommand.Execute(null);
        Assert.False(panel.IsOpen);
    }

    [Fact]
    public async Task Panel_Submit_Answers_ThroughEngine()
    {
        var panel = new AskPanelViewModel(FullContext, new ImmediateDispatcher());
        panel.Question = "What did my last scan find?";

        panel.SubmitCommand.Execute(null);
        var answer = await WaitForAnswer(panel);

        Assert.Contains("4102", answer.Fact);
        Assert.True(panel.ActionVisible);
        Assert.False(panel.IsBusy);
        Assert.Contains("Grounded", panel.StatusLabel);
    }

    [Fact]
    public async Task Panel_Chip_Submits_And_ExposesAction()
    {
        var panel = new AskPanelViewModel(EmptyContext, new ImmediateDispatcher());

        panel.ChipCommand.Execute("Start a Balanced scan");
        var answer = await WaitForAnswer(panel);

        Assert.Equal("Start a Balanced scan", panel.Question);
        Assert.Equal("StartBalancedScan", answer.Action?.Kind);
        Assert.Equal("Start Balanced scan", panel.ActionLabel);
    }

    [Fact]
    public void Panel_EmptyQuestion_IsNoOp()
    {
        var panel = new AskPanelViewModel(FullContext, new ImmediateDispatcher());
        panel.Question = "   ";

        panel.SubmitCommand.Execute(null);

        Assert.Null(panel.Answer);
        Assert.False(panel.IsBusy);
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
}
