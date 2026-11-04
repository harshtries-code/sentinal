using Sentinel.App.ViewModels;
using Sentinel.Store;

namespace Sentinel.Tests;

// U22: Storage board view-model behavior — the map/table toggle,
// ranked-row math, and the risk-mix selection summary. Rendered
// pixels + UI Automation states are proven separately in the VM
// driver leg (u22 evidence); these pin the view-model contract.
public sealed class StorageBoardTests : IDisposable
{
    private readonly string _dir;
    private readonly string _dbPath;

    public StorageBoardTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "sentinel-u22-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _dbPath = Path.Combine(_dir, "t.db");
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

    [Fact]
    public void MapView_DefaultsToMap_Toggles()
    {
        var vm = new CleanerViewModel(OpenDb, () => []);
        vm.Refresh();

        Assert.Equal("Map", vm.MapViewMode);
        Assert.True(vm.ShowMap);
        Assert.False(vm.ShowTable);

        vm.SetMapView("Table");
        Assert.Equal("Table", vm.MapViewMode);
        Assert.False(vm.ShowMap);
        Assert.True(vm.ShowTable);

        vm.SetMapView("bogus");
        Assert.Equal("Map", vm.MapViewMode);
        Assert.True(vm.ShowMap);
    }

    [Fact]
    public void RankedRows_MatchTreemap_Math()
    {
        var cats = new List<TreemapCategory>
        {
            new("User files", 300, [], 300, 3),
            new("Other", 100, [], 100, 1),
        };
        var rows = CleanerViewModel.BuildRankedRows(cats);

        Assert.Equal(2, rows.Count);
        Assert.Equal("User files", rows[0].Key);
        Assert.Equal("75%", rows[0].Share);
        Assert.True(rows[0].Scopable);
        Assert.Equal("Other", rows[1].Key);
        Assert.Equal("25%", rows[1].Share);
        Assert.False(rows[1].Scopable);
        Assert.Contains("file", rows[0].Files);
    }

    [Fact]
    public void RankedRows_EmptyTotal_ShowsDash()
    {
        var rows = CleanerViewModel.BuildRankedRows([]);
        Assert.Empty(rows);
        var zero = CleanerViewModel.BuildRankedRows(
            [new TreemapCategory("Other", 0, [], 0, 0)]);
        Assert.Equal("—", zero[0].Share);
    }

    [Fact]
    public void Refresh_PopulatesRankedRows_FromTreemap()
    {
        string file = Path.Combine(_dir, "seed.dat");
        File.WriteAllBytes(file, new byte[100]);
        using (var db = OpenDb())
        {
            db.UpsertFingerprint(file, 100, DateTime.UtcNow.Ticks, null, 1);
        }

        var vm = new CleanerViewModel(OpenDb, () => []);
        vm.Refresh();

        Assert.NotEmpty(vm.Treemap);
        Assert.Equal(vm.Treemap.Count, vm.RankedRows.Count);
        Assert.Equal(
            vm.Treemap.Select(c => c.Key).Order().ToList(),
            vm.RankedRows.Select(r => r.Key).Order().ToList());
    }

    [Fact]
    public void CheckedLine_ShowsRiskMix_NotCleanup()
    {
        string big = Path.Combine(_dir, "big-review.tmp");
        string small = Path.Combine(_dir, "small-safe.txt");
        File.WriteAllBytes(big, new byte[10_000_000]);
        File.WriteAllBytes(small, new byte[10]);
        using (var db = OpenDb())
        {
            db.UpsertFingerprint(big, 10_000_000, DateTime.UtcNow.Ticks, null, 1);
            db.UpsertFingerprint(small, 10, DateTime.UtcNow.Ticks, null, 1);
        }

        var vm = new CleanerViewModel(OpenDb, () => []);
        vm.Refresh();
        Assert.Equal("Nothing selected", vm.CheckedLine);

        var first = vm.VisibleRows.First(r => r.Detail.FullPath == big);
        var second = vm.VisibleRows.First(r => r.Detail.FullPath == small);
        first.IsSelected = true;
        second.IsSelected = true;

        Assert.StartsWith("2 items · ", vm.CheckedLine);
        // Both selected tiers appear by name; nothing names cleanup.
        Assert.Contains(TierLabel(first.Tier), vm.CheckedLine);
        Assert.Contains(TierLabel(second.Tier), vm.CheckedLine);
        Assert.DoesNotContain("cleanup", vm.CheckedLine, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("delete", vm.CheckedLine, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("preview", vm.CheckedLine, StringComparison.OrdinalIgnoreCase);
    }

    private static string TierLabel(string tier) => tier switch
    {
        "SAFE" => "safe",
        "REVIEW" => "review",
        "NEVER" => "never-touch",
        _ => tier.ToLowerInvariant(),
    };

    [Fact]
    public void CheckedLine_GroupRows_CountByKind()
    {
        string a = Path.Combine(_dir, "dup-a.dat");
        string b = Path.Combine(_dir, "dup-b.dat");
        File.WriteAllBytes(a, new byte[50]);
        File.WriteAllBytes(b, new byte[50]);
        using (var db = OpenDb())
        {
            db.UpsertFingerprint(a, 50, DateTime.UtcNow.Ticks, "dup-u22", 1);
            db.UpsertFingerprint(b, 50, DateTime.UtcNow.Ticks, "dup-u22", 1);
        }

        var vm = new CleanerViewModel(OpenDb, () => []);
        vm.Refresh();
        vm.SelectedChip = "Duplicates";
        var row = Assert.Single(vm.VisibleRows);
        row.IsSelected = true;

        Assert.Contains("1 items", vm.CheckedLine);
        Assert.Contains("1 duplicates", vm.CheckedLine);
    }

    [Fact]
    public void NeverRow_Visible_ButNotSelectable()
    {
        string keep = Path.Combine(_dir, "keep.dat");
        File.WriteAllBytes(keep, new byte[20]);
        using (var db = OpenDb())
        {
            db.UpsertFingerprint(keep, 20, DateTime.UtcNow.Ticks, null, 1);
        }

        var vm = new CleanerViewModel(OpenDb, () => [_dir]);
        vm.Refresh();
        vm.SelectedChip = "Never";

        var row = Assert.Single(vm.VisibleRows);
        Assert.False(row.IsSelectable);
        row.IsSelected = true; // refused: protected rows never check
        Assert.False(row.IsSelected);
        Assert.Equal("Nothing selected", vm.CheckedLine);
    }
}
