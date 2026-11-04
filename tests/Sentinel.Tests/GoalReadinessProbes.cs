using Sentinel.App.Services;
using Sentinel.App.ViewModels;
using Sentinel.Store;
using Xunit;

namespace Sentinel.Tests;

// Independent acceptance probes (audit 2026-11-02-goal-review, adopted verbatim
// by A02). They failed on the pre-A02 tree; the builder fixes the behavior, not
// the assertions — except where A02's wording decision explicitly redefines a
// user-facing string, which is recorded in goal/evidence/a02/.
public sealed class GoalReadinessProbes : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "sentinel-goal-probe-" + Guid.NewGuid().ToString("N"));
    public GoalReadinessProbes() => Directory.CreateDirectory(_root);
    private SentinelDb OpenDb() => new(Path.Combine(_root, "scan.db"));
    private AgentStore OpenAgent() => new(Path.Combine(_root, "agent.db"));

    [Fact]
    public void ProtectedStorage_RemainsInspectable_AndCannotBeSelected()
    {
        string file = Path.Combine(_root, "protected", "important.dat");
        using (var db = OpenDb())
            db.UpsertFingerprint(file, 1234, DateTime.UtcNow.Ticks, null, 1);
        var page = new CleanerViewModel(OpenDb, () => [Path.Combine(_root, "protected")]);
        page.Refresh();
        page.SelectedChip = "Never";
        var row = Assert.Single(page.VisibleRows);
        Assert.Equal(file, row.Detail.FullPath);
        Assert.False(row.IsSelectable);
        row.IsSelected = true;
        Assert.False(row.IsSelected);
    }

    [Fact]
    public void StorageScopeLabel_MatchesTheInventoryBeingTotalled()
    {
        string scopeA = Path.Combine(_root, "A"), scopeB = Path.Combine(_root, "B");
        using (var db = OpenDb())
        {
            db.UpsertFingerprint(Path.Combine(scopeA, "a.dat"), 100, DateTime.UtcNow.Ticks, null, 1);
            long a = db.BeginRun(scopeA, 1, "Balanced");
            db.EndRun(a, 1, 100, 0, 1);
            db.UpsertFingerprint(Path.Combine(scopeB, "b.dat"), 200, DateTime.UtcNow.Ticks, null, 2);
            long b = db.BeginRun(scopeB, 2, "Balanced");
            db.EndRun(b, 1, 200, 0, 1);
        }
        var page = new CleanerViewModel(OpenDb, () => []);
        var snapshot = CleanerViewModel.Collect(OpenDb, []);
        page.Apply(snapshot);
        // Either display B's 200 bytes, or explicitly label a multi-scope total.
        // Merely labelling the full retained inventory as B is misleading.
        Assert.True(snapshot.TotalBytes == 200 || !page.ScopeLine.StartsWith(scopeB),
            $"Scope label is {page.ScopeLine}, but total is {snapshot.TotalBytes}; B contains 200 bytes.");
    }

    [Fact]
    public void PayloadInspector_CanShowTheMostRecentRequest()
    {
        var page = new SettingsViewModel(new SettingsStore(Path.Combine(_root, "settings.json")), OpenDb, OpenAgent, () => _root);
        page.PayloadProvider = () => Enumerable.Range(1, 8).Select(i => $"synthetic-request-{i}-end").ToList();
        page.ShowPayloadsCommand.Execute(null);
        Assert.Contains("synthetic-request-8-end", page.PayloadPreview);
    }

    public void Dispose()
    {
        // Exact GUID-owned fixture directory only. No links or external content created.
        try { Directory.Delete(_root, true); } catch { }
    }
}
