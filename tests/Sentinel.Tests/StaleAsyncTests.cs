using System.Text.RegularExpressions;
using Sentinel.App.Services;
using Sentinel.App.ViewModels;
using Sentinel.Engine.Agent;
using Sentinel.Engine.Scan;
using Sentinel.Engine.SystemInventory;
using Sentinel.Store;

namespace Sentinel.Tests;

// A09: stale asynchronous results are rejected. Page collects
// are versioned (newest token wins), Threats detail reads are
// bound to their selection/request, faults surface as
// observable errors with last data kept, and superseded scans
// cannot paint over their successor.
public sealed class StaleAsyncTests : IDisposable
{
    private readonly string _dir;
    private readonly string _scopeA;
    private readonly string _scopeB;
    private readonly string _dbPath;
    private readonly string _agentDbPath;

    public StaleAsyncTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "sentinel-a09-" + Guid.NewGuid().ToString("N"));
        _scopeA = Path.Combine(_dir, "a");
        _scopeB = Path.Combine(_dir, "b");
        Directory.CreateDirectory(_scopeA);
        Directory.CreateDirectory(_scopeB);
        File.WriteAllText(Path.Combine(_scopeA, "a.txt"), "alpha");
        File.WriteAllText(Path.Combine(_scopeB, "b1.txt"), "one");
        File.WriteAllText(Path.Combine(_scopeB, "b2.txt"), "two");
        File.WriteAllText(Path.Combine(_scopeB, "b3.txt"), "three");
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

    [Fact]
    public void Tracker_Next_Invalidates_Older_Token()
    {
        var tracker = new RefreshTracker();
        long first = tracker.Next();
        Assert.True(tracker.IsCurrent(first));
        long second = tracker.Next();
        Assert.False(tracker.IsCurrent(first));
        Assert.True(tracker.IsCurrent(second));
    }

    [Fact]
    public void Tracker_Success_Stamps_And_Clears_Error()
    {
        var tracker = new RefreshTracker();
        tracker.NoteFault("thing", new InvalidOperationException("boom"));
        Assert.NotNull(tracker.Error);

        tracker.NoteSuccess();
        Assert.Null(tracker.Error);
        Assert.NotNull(tracker.AppliedAt);
        Assert.True((DateTime.UtcNow - tracker.AppliedAt.Value).TotalMinutes < 5);
    }

    [Fact]
    public void Tracker_Fault_Ages_Last_Data()
    {
        var tracker = new RefreshTracker();
        tracker.NoteFault("thing", new InvalidOperationException("boom"));
        Assert.Contains("Nothing to show yet", tracker.Error);

        tracker.NoteSuccess();
        tracker.NoteFault("thing", new IOException("gone"));
        Assert.Contains("IOException", tracker.Error);
        Assert.Contains("showing data from", tracker.Error);
        Assert.NotNull(tracker.AppliedAt);
    }

    [Fact]
    public async Task PageRefresh_Success_Applies_And_Stamps()
    {
        var tracker = new RefreshTracker();
        string? seen = null;
        bool done = false;
        await PageRefresh.Run(
            tracker, () => "fresh", s => seen = s, "thing",
            TaskScheduler.Default, () => done = true);

        Assert.Equal("fresh", seen);
        Assert.Null(tracker.Error);
        Assert.NotNull(tracker.AppliedAt);
        Assert.True(done);
    }

    [Fact]
    public async Task PageRefresh_Fault_Records_Preserves_RunsDone()
    {
        var tracker = new RefreshTracker();
        bool applied = false;
        bool done = false;
        // The helper never faults itself: awaiting is safe.
        await PageRefresh.Run<string>(
            tracker,
            () => throw new InvalidOperationException("boom"),
            _ => applied = true,
            "thing", TaskScheduler.Default, () => done = true);

        Assert.False(applied);
        Assert.Contains("InvalidOperationException", tracker.Error);
        Assert.Contains("Nothing to show yet", tracker.Error);
        Assert.True(done);
    }

    [Fact]
    public async Task PageRefresh_Stale_Token_Dropped()
    {
        var tracker = new RefreshTracker();
        using var gate = new ManualResetEventSlim(false);
        bool applied = false;
        var run = PageRefresh.Run(
            tracker,
            () =>
            {
                gate.Wait(TimeSpan.FromSeconds(10));
                return "stale";
            },
            _ => applied = true,
            "thing", TaskScheduler.Default);

        // A newer request supersedes the in-flight collect.
        tracker.Next();
        gate.Set();
        await run;

        Assert.False(applied);
        Assert.Null(tracker.AppliedAt);
    }

    [Fact]
    public async Task PageRefresh_Apply_Throw_Becomes_Error()
    {
        var tracker = new RefreshTracker();
        bool done = false;
        await PageRefresh.Run(
            tracker, () => "x",
            _ => throw new InvalidOperationException("apply blew up"),
            "thing", TaskScheduler.Default, () => done = true);

        Assert.Contains("InvalidOperationException", tracker.Error);
        Assert.True(done);
    }

    [Fact]
    public void Threats_Old_Hash_Never_Attaches_To_New_Row()
    {
        var vm = new ThreatsViewModel();
        vm.SelectedDetection = new ThreatDetectionRow("A", "High", @"C:\a", "now", "", false);
        long tokenA = vm.BeginDetectionEvidence();
        vm.SelectedDetection = new ThreatDetectionRow("B", "High", @"C:\b", "now", "", false);
        long tokenB = vm.BeginDetectionEvidence();

        // A's slow read lands after B was selected: dropped.
        vm.SetDetectionEvidence(
            tokenA,
            new StaticFileEvidenceRecord(@"C:\a", true, 10, "AAA", false, null, null, null),
            @"C:\a");
        Assert.Null(vm.DetectionEvidence);

        vm.SetDetectionEvidence(
            tokenB,
            new StaticFileEvidenceRecord(@"C:\b", true, 10, "BBB", false, null, null, null),
            @"C:\b");
        Assert.Equal("BBB", vm.DetectionEvidence!.HashDisplay);
    }

    [Fact]
    public void Threats_Stale_Fault_Never_Overwrites_Good_Evidence()
    {
        var vm = new ThreatsViewModel();
        vm.SelectedDetection = new ThreatDetectionRow("A", "High", @"C:\a", "now", "", false);
        long tokenA = vm.BeginDetectionEvidence();
        vm.SelectedDetection = new ThreatDetectionRow("B", "High", @"C:\b", "now", "", false);
        long tokenB = vm.BeginDetectionEvidence();
        vm.SetDetectionEvidence(
            tokenB,
            new StaticFileEvidenceRecord(@"C:\b", true, 10, "BBB", false, null, null, null),
            @"C:\b");

        // A's read failed after B already attached: the failure
        // line must not clobber B's evidence.
        vm.SetDetectionEvidence(tokenA, null, @"C:\a");
        Assert.Equal("BBB", vm.DetectionEvidence!.HashDisplay);
    }

    [Fact]
    public void Threats_Apply_Invalidates_InFlight_Evidence()
    {
        var vm = new ThreatsViewModel();
        vm.SelectedDetection = new ThreatDetectionRow("A", "High", @"C:\a", "now", "", false);
        long tokenA = vm.BeginDetectionEvidence();
        vm.Apply(new ThreatsViewModel.ThreatsSnapshot(
            "b", "d", "On", "Today", "Today", "c", [], [], [], 0, 0, 0, "n"));

        vm.SetDetectionEvidence(
            tokenA,
            new StaticFileEvidenceRecord(@"C:\a", true, 10, "AAA", false, null, null, null),
            @"C:\a");
        Assert.Null(vm.DetectionEvidence);
    }

    [Fact]
    public void Threats_Channels_Do_Not_Invalidate_Each_Other()
    {
        var vm = new ThreatsViewModel();
        vm.SelectedDetection = new ThreatDetectionRow("A", "High", @"C:\a", "now", "", false);
        long evidence = vm.BeginDetectionEvidence();

        // A page collect starting must not kill the detail read.
        long page = vm.RefreshState.Next();
        vm.SetDetectionEvidence(
            evidence,
            new StaticFileEvidenceRecord(@"C:\a", true, 10, "AAA", false, null, null, null),
            @"C:\a");
        Assert.Equal("AAA", vm.DetectionEvidence!.HashDisplay);

        // And a detail read must not kill the page collect.
        vm.BeginDetectionEvidence();
        Assert.True(vm.RefreshState.IsCurrent(page));
    }

    [Fact]
    public void Threats_Only_Newest_FileCheck_Attaches()
    {
        var vm = new ThreatsViewModel();
        long first = vm.BeginFileCheck();
        long second = vm.BeginFileCheck();

        vm.SetFileCheck(
            first,
            new StaticFileEvidenceRecord(@"C:\old.txt", true, 5, "OLD", false, null, null, null),
            @"C:\old.txt", null);
        Assert.Null(vm.FileCheck);

        vm.SetFileCheck(
            second,
            new StaticFileEvidenceRecord(@"C:\new.txt", true, 5, "NEW", false, null, null, null),
            @"C:\new.txt", null);
        Assert.Equal("NEW", vm.FileCheck!.HashDisplay);
    }

    [Fact]
    public async Task Crashes_RefreshAsync_Success_Seam_Stamps()
    {
        var vm = new CrashesViewModel();
        await vm.RefreshAsync(() => new CrashesViewModel.CrashesSnapshot("S", "C", [], []));

        Assert.Equal("S", vm.Summary);
        Assert.Null(vm.RefreshState.Error);
        Assert.NotNull(vm.RefreshState.AppliedAt);
        Assert.False(vm.IsRefreshing);
    }

    [Fact]
    public async Task Crashes_RefreshAsync_Fault_Keeps_Last_Rows()
    {
        var vm = new CrashesViewModel();
        vm.Refresh();
        string summary = vm.Summary;
        int rows = vm.Timeline.Count;

        await vm.RefreshAsync(() => throw new InvalidOperationException("boom"));

        Assert.Contains("InvalidOperationException", vm.RefreshState.Error);
        Assert.Contains("showing data from", vm.RefreshState.Error);
        Assert.Equal(summary, vm.Summary);
        Assert.Equal(rows, vm.Timeline.Count);
        Assert.False(vm.IsRefreshing);
    }

    [Fact]
    public async Task History_RefreshAsync_Fault_Keeps_Last_Lists()
    {
        using (var seed = new SentinelDb(_dbPath))
        {
            long id = seed.BeginRun(_scopeA, 1, "Balanced");
            seed.EndRun(id, 1, 100, 0, 500, "Completed", null, 0);
        }

        var vm = new HistoryViewModel(
            () => new SentinelDb(_dbPath), () => new AgentStore(_agentDbPath));
        await vm.RefreshAsync();
        Assert.Single(vm.Runs);
        var stamped = vm.RefreshState.AppliedAt;
        Assert.NotNull(stamped);

        await vm.RefreshAsync(() => throw new IOException("disk gone"));

        Assert.Contains("IOException", vm.RefreshState.Error);
        Assert.Contains("showing data from", vm.RefreshState.Error);
        Assert.Single(vm.Runs);
        Assert.Equal(stamped, vm.RefreshState.AppliedAt);
        Assert.False(vm.IsRefreshing);
    }

    [Fact]
    public async Task Reports_GenerateAsync_Fault_Keeps_Last_Draft()
    {
        var vm = new ReportsViewModel(() => new SentinelDb(_dbPath));
        vm.Generate();
        var draft = vm.Draft;
        Assert.NotNull(draft);

        await vm.GenerateAsync(() => throw new UnauthorizedAccessException("denied"));

        Assert.Contains("UnauthorizedAccessException", vm.RefreshState.Error);
        Assert.Contains("showing data from", vm.RefreshState.Error);
        Assert.Same(draft, vm.Draft);
        Assert.False(vm.IsGenerating);
    }

    [Fact]
    public void StatusBar_Refresh_After_Dispose_Is_Silent()
    {
        var vm = new StatusBarViewModel(() => Path.Combine(_dir, "missing.db"));
        vm.Refresh();
        string resources = vm.SelfResources;
        vm.Dispose();

        // A timer tick racing OnClosed must not throw.
        vm.Refresh();
        Assert.Equal(resources, vm.SelfResources);
    }

    [Fact]
    public async Task Session_Replacement_Drops_Superseded_Investigator()
    {
        var gateA = new GateFindingModel();
        int calls = 0;
        var vm = new ScanSessionViewModel(
            () => new SentinelDb(_dbPath), null, new ImmediateDispatcher(),
            () => new AgentStore(_agentDbPath), () => true,
            (tools, http, payloads, budgets) => ++calls == 1
                ? new ModelSource(gateA, "test gated", false)
                : new ModelSource(new InstantDoneModel(), "test instant", false));

        vm.Start(ScanMode.Balanced, _scopeA);
        await gateA.Entered.WaitAsync(TimeSpan.FromSeconds(20));
        await vm.RunningTask!.WaitAsync(TimeSpan.FromSeconds(60));
        Assert.Equal(ScanSessionState.Completed, vm.State);
        var investigatorA = vm.InvestigatorTask!;

        // A's collection is done but its investigator is still
        // gated: starting B supersedes it.
        Assert.True(vm.CanStart);
        vm.Start(ScanMode.Balanced, _scopeB);
        gateA.Release();
        await investigatorA.WaitAsync(TimeSpan.FromSeconds(20));
        await vm.RunningTask!.WaitAsync(TimeSpan.FromSeconds(60));
        await vm.InvestigatorTask!.WaitAsync(TimeSpan.FromSeconds(20));
        await vm.ReconcileTask!.WaitAsync(TimeSpan.FromSeconds(20));

        // A's finding posts were dropped: B's outcome stands.
        Assert.Equal(ScanSessionState.Completed, vm.State);
        Assert.Equal("AI: done — no findings.", vm.InvestigationLine);
        Assert.Empty(vm.ProvisionalFindings);
        Assert.Contains("3 files", vm.Counts);
        Assert.Equal(_scopeB, vm.LastRoot);
    }

    // First turn queries inventory; second turn waits for the
    // test gate, then emits a finding (like FindingModel).
    private sealed class GateFindingModel : IInvestigationModel
    {
        public string Name => "gate-finding-test-double";

        private readonly TaskCompletionSource _entered = new();
        private readonly TaskCompletionSource _gate = new();
        private int _turns;
        private bool _emitted;

        public Task Entered => _entered.Task;

        public void Release() => _gate.TrySetResult();

        public async Task<ModelTurn> GetNextStepAsync(string contextJson, CancellationToken ct)
        {
            _entered.TrySetResult();
            ct.ThrowIfCancellationRequested();
            _turns++;
            if (_turns == 1)
            {
                return new ModelTurn(
                    new ToolCallRequest("query_inventory", new Dictionary<string, string>
                    {
                        ["limit"] = "50",
                    }),
                    null, false, null);
            }

            if (!_emitted)
            {
                await _gate.Task.WaitAsync(ct).ConfigureAwait(false);
                _emitted = true;
                string? id = Regex.Matches(contextJson, @"f:\d+")
                    .Select(m => m.Value).FirstOrDefault();
                return new ModelTurn(null, new FindingDraft(
                    "Saw " + (id ?? "f:0") + " via tool results.",
                    "Test-double interpretation.",
                    id is null ? [] : [id], string.Empty, string.Empty), false, null);
            }

            return new ModelTurn(null, null, true, "Explored.");
        }
    }

    private sealed class InstantDoneModel : IInvestigationModel
    {
        public string Name => "instant-done-test-double";

        public Task<ModelTurn> GetNextStepAsync(string contextJson, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            return Task.FromResult(new ModelTurn(null, null, true, "Explored."));
        }
    }

    [Fact]
    public void Tracker_Busy_Counts_Overlapping_Collects()
    {
        var tracker = new RefreshTracker();
        Assert.False(tracker.IsRefreshing);

        tracker.MarkBusy("drivers");
        Assert.True(tracker.IsRefreshing);
        Assert.Equal("Loading drivers…", tracker.LoadingText);

        tracker.MarkBusy("drivers");
        tracker.MarkIdle();
        Assert.True(tracker.IsRefreshing); // One still in flight: no flicker.

        tracker.MarkIdle();
        Assert.False(tracker.IsRefreshing);
    }

    [Fact]
    public void Tracker_Idle_Never_Goes_Negative()
    {
        var tracker = new RefreshTracker();
        tracker.MarkIdle();
        tracker.MarkIdle();
        Assert.False(tracker.IsRefreshing);

        tracker.MarkBusy("x");
        Assert.True(tracker.IsRefreshing);
    }

    [Fact]
    public async Task PageRefresh_Marks_Busy_During_Slow_Collect()
    {
        var tracker = new RefreshTracker();
        using var entered = new ManualResetEventSlim(false);
        using var release = new ManualResetEventSlim(false);
        string? applied = null;

        var run = PageRefresh.Run(
            tracker,
            () =>
            {
                entered.Set();
                // Long gate: only the test's own release (or a hung
                // test host) ends the collect; a short timeout here
                // would turn host load into a false failure.
                release.Wait(TimeSpan.FromSeconds(60));
                return "rows";
            },
            result => applied = result,
            "drivers",
            TaskScheduler.Default);
        Assert.True(entered.Wait(TimeSpan.FromSeconds(10)));
        Assert.True(tracker.IsRefreshing);
        Assert.Equal("Loading drivers…", tracker.LoadingText);

        release.Set();
        await run;
        Assert.False(tracker.IsRefreshing);
        Assert.Equal("rows", applied);
        Assert.Null(tracker.Error);
    }

    [Fact]
    public async Task PageRefresh_Clears_Busy_On_Fault()
    {
        var tracker = new RefreshTracker();
        await PageRefresh.Run<string>(
            tracker,
            () => throw new InvalidOperationException("boom"),
            _ => Assert.Fail("apply must not run"),
            "drivers",
            TaskScheduler.Default);
        Assert.False(tracker.IsRefreshing);
        Assert.Contains("Couldn't load drivers", tracker.Error);
    }
}
