using Sentinel.App.ViewModels;
using Sentinel.Store;

namespace Sentinel.Tests;

// A07: scan scope and generation attribution. DB-fixture tests
// (no VM): counts, treemap, scope labels, and reports bind to
// the same completed scope/generation, or explicitly label
// retained multi-scope history. Old inventory is never silently
// called current.
public sealed class ScanScopeTests : IDisposable
{
    private readonly string _dir;
    private readonly string _dbPath;

    public ScanScopeTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "sentinel-a07-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _dbPath = Path.Combine(_dir, "scan.db");
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

    private SentinelDb OpenDb() => new(_dbPath);

    private static void CompleteRun(SentinelDb db, string root, int generation, int gaps = 0)
    {
        long id = db.BeginRun(root, generation, "Balanced");
        db.EndRun(id, 1, 100, 0, 1000, "Completed", null, gaps);
    }

    [Fact]
    public void CancelledLatestRun_BindsToLastCompleted()
    {
        string scopeA = Path.Combine(_dir, "A");
        string scopeB = Path.Combine(_dir, "B");
        using (var db = OpenDb())
        {
            // Scope A completed (gen 1, 2 gaps); scope B cancelled
            // (gen 2 rolled back — its rows never persisted).
            db.UpsertFingerprint(Path.Combine(scopeA, "a.dat"), 100, DateTime.UtcNow.Ticks, null, 1);
            CompleteRun(db, scopeA, 1, gaps: 2);
            db.RecordAbortedRun(scopeB, 2, 0, 0, 0, 500, "Cancelled", null, "Balanced");
        }

        var vm = new CleanerViewModel(OpenDb, () => []);
        vm.Apply(CleanerViewModel.Collect(OpenDb, []));

        // Totals are A's alone; the label must not claim B.
        Assert.False(vm.ScopeLine.StartsWith(scopeB, StringComparison.Ordinal));
        Assert.Contains("2 locations", vm.ScopeLine);
        // The aborted attempt is named, not silent — and it must
        // not wipe the completed run's gap count to "None".
        Assert.Contains("latest attempt cancelled", vm.LastScanLine);
        Assert.Contains("2 locations unavailable", vm.UnavailableLine);
    }

    [Fact]
    public void OnlyCancelledRun_NeverCallsItCurrent()
    {
        using (var db = OpenDb())
        {
            db.RecordAbortedRun(Path.Combine(_dir, "B"), 1, 0, 0, 0, 500, "Cancelled", null, "Balanced");
        }

        var vm = new CleanerViewModel(OpenDb, () => []);
        vm.Apply(CleanerViewModel.Collect(OpenDb, []));

        Assert.Equal("Not inspected yet.", vm.Summary);
        Assert.Contains("No completed scan yet", vm.ScopeLine);
        Assert.Equal("Last scan: never", vm.LastScanLine);
        Assert.Equal("—", vm.UnavailableLine);
    }

    [Fact]
    public void FailedLatestRun_KeepsCompletedGaps_AndNamesAttempt()
    {
        string scopeA = Path.Combine(_dir, "A");
        using (var db = OpenDb())
        {
            db.UpsertFingerprint(Path.Combine(scopeA, "a.dat"), 100, DateTime.UtcNow.Ticks, null, 1);
            CompleteRun(db, scopeA, 1, gaps: 1);
            db.RecordAbortedRun(Path.Combine(_dir, "B"), 2, 0, 0, 0, 500, "Failed", "IOException", "Balanced");
        }

        var vm = new CleanerViewModel(OpenDb, () => []);
        vm.Apply(CleanerViewModel.Collect(OpenDb, []));

        Assert.Contains("latest attempt failed", vm.LastScanLine);
        Assert.Contains("1 location unavailable", vm.UnavailableLine);
    }

    [Fact]
    public void DeltaLabel_ExcludedFromLocationCount()
    {
        using (var db = OpenDb())
        {
            db.UpsertFingerprint(Path.Combine(_dir, "a.dat"), 100, DateTime.UtcNow.Ticks, null, 1);
            CompleteRun(db, _dir, 1);
            CompleteRun(db, "delta", 2);
        }

        var vm = new CleanerViewModel(OpenDb, () => []);
        vm.Apply(CleanerViewModel.Collect(OpenDb, []));

        // One real location: "delta" rescans stamp rows, they are
        // not a place. Single-scope branch shows the real root.
        Assert.Contains(_dir, vm.ScopeLine);
        Assert.DoesNotContain("2 locations", vm.ScopeLine);
    }

    [Fact]
    public void MultiRootRunLabel_SplitsIntoLocations()
    {
        string scopeA = Path.Combine(_dir, "A");
        string scopeB = Path.Combine(_dir, "B");
        using (var db = OpenDb())
        {
            db.UpsertFingerprint(Path.Combine(scopeA, "a.dat"), 100, DateTime.UtcNow.Ticks, null, 1);
            db.UpsertFingerprint(Path.Combine(scopeB, "b.dat"), 200, DateTime.UtcNow.Ticks, null, 1);
            CompleteRun(db, scopeA + ";" + scopeB, 1);
        }

        var vm = new CleanerViewModel(OpenDb, () => []);
        vm.Apply(CleanerViewModel.Collect(OpenDb, []));

        Assert.Contains("2 locations", vm.ScopeLine);
    }

    [Fact]
    public void InventoryGeneration_AdvancesOnRescan()
    {
        string scope = Path.Combine(_dir, "scope");
        using (var db = OpenDb())
        {
            db.UpsertFingerprint(Path.Combine(scope, "a.dat"), 100, DateTime.UtcNow.Ticks, null, 1);
            CompleteRun(db, scope, 1);
        }

        var vm = new CleanerViewModel(OpenDb, () => []);
        vm.Apply(CleanerViewModel.Collect(OpenDb, []));
        Assert.Contains("generation 1", vm.Coverage);

        using (var db = OpenDb())
        {
            db.UpsertFingerprint(Path.Combine(scope, "b.dat"), 200, DateTime.UtcNow.Ticks, null, 2);
            CompleteRun(db, scope, 2);
        }

        // A re-collect after the new scan binds to the NEW
        // generation — pages never serve cached older totals.
        vm.Apply(CleanerViewModel.Collect(OpenDb, []));
        Assert.Contains("generation 2", vm.Coverage);
        Assert.Contains("2 files", vm.Summary);
    }

    [Fact]
    public void OverlappingRoots_MergeWithoutDoubleCount()
    {
        string scope = Path.Combine(_dir, "scope");
        string sub = Path.Combine(scope, "sub");
        string shared = Path.Combine(sub, "shared.dat");
        using (var db = OpenDb())
        {
            // Gen 1 saw the parent scope; gen 2 re-saw the
            // overlapping child. Same path = same row, re-stamped.
            db.UpsertFingerprint(shared, 100, DateTime.UtcNow.Ticks, null, 1);
            CompleteRun(db, scope, 1);
            db.UpsertFingerprint(shared, 100, DateTime.UtcNow.Ticks, null, 2);
            CompleteRun(db, sub, 2);
        }

        var vm = new CleanerViewModel(OpenDb, () => []);
        var snapshot = CleanerViewModel.Collect(OpenDb, []);
        vm.Apply(snapshot);

        Assert.Equal(1L, snapshot.TotalFiles);
        Assert.Equal(100L, snapshot.TotalBytes);
        Assert.Contains("1 file", vm.Summary);
    }

    [Fact]
    public void Reports_MultiScope_StorageLine_LabelsLocations()
    {
        string scopeA = Path.Combine(_dir, "A");
        string scopeB = Path.Combine(_dir, "B");
        using (var db = OpenDb())
        {
            db.UpsertFingerprint(Path.Combine(scopeA, "a.dat"), 100, DateTime.UtcNow.Ticks, null, 1);
            CompleteRun(db, scopeA, 1);
            db.UpsertFingerprint(Path.Combine(scopeB, "b.dat"), 200, DateTime.UtcNow.Ticks, null, 2);
            CompleteRun(db, scopeB, 2);
        }

        var vm = new ReportsViewModel(OpenDb);
        vm.Generate();

        // Scope names the latest completed run, but the storage
        // totals span retained history — the line must say so.
        Assert.Contains(scopeB, vm.Draft!.ScanScope);
        Assert.Contains("across 2 locations", vm.Draft.Storage);
    }

    [Fact]
    public void Reports_SingleScope_StorageLine_Unchanged()
    {
        using (var db = OpenDb())
        {
            db.UpsertFingerprint(Path.Combine(_dir, "a.dat"), 100, DateTime.UtcNow.Ticks, null, 1);
            CompleteRun(db, _dir, 1);
        }

        var vm = new ReportsViewModel(OpenDb);
        vm.Generate();

        Assert.DoesNotContain("across", vm.Draft!.Storage);
        Assert.Contains("inventoried", vm.Draft.Storage);
    }
}
