using Sentinel.App.ViewModels;
using Sentinel.Engine.SystemInventory;
using Sentinel.Store;

namespace Sentinel.Tests;

// U21: Overview and evidence relationships — top-three cap,
// last scan with mode/duration, generation on activity, graph
// zoom/inspect, and deep links that carry scope.
public sealed class OverviewExperienceTests
{
    private static OverviewViewModel.OverviewSnapshot Snapshot(
        CleanerViewModel.CleanerSnapshot? cleaner,
        CollectionResult<DeviceProblemRecord> problems,
        CollectionResult<DefenderDetectionRecord> detections,
        CollectionResult<EventRecord> events,
        IReadOnlyList<ScanRunInfo> runs,
        IReadOnlyList<InvestigationState> investigations)
    {
        var failStartups = CollectionResult<StartupRecord>.Fail("t", "t");
        var failDrivers = CollectionResult<DriverRecord>.Fail("t", "t");
        var failWarnings = CollectionResult<TargetedEventRecord>.Fail("t", "t");
        var failTopology = CollectionResult<DiskTopologyRecord>.Fail("t", "t");
        var failBatteries = CollectionResult<BatteryRecord>.Fail("t", "t");
        var failDisks = CollectionResult<DiskHealthRecord>.Fail("t", "t");
        var failStatus = CollectionResult<DefenderStatusRecord>.Fail("t", "t");
        return new OverviewViewModel.OverviewSnapshot(
            failStartups, failStartups, failDrivers, problems, events,
            failWarnings, failTopology, failBatteries, failDisks,
            failStatus, detections, cleaner, null, runs, investigations);
    }

    private static OverviewViewModel Panel() => new(() => null!, () => null!, () => []);

    private static CleanerViewModel.CleanerSnapshot CleanerWith(
        params ClassifiedRow[] top)
    {
        return new CleanerViewModel.CleanerSnapshot(
            0, 0, string.Empty, [], 0, 0, [],
            new AttrStats(0, 0, 0, 0, 0), string.Empty, [], [], 0, 0,
            [], null, null, 0, null, 0, top, null, null, [], []);
    }

    private static ClassifiedRow Review(string path) => new(
        path, "1 MB", "Review", "old download", null, 1000, "today", null);

    [Fact]
    public void BuildFindings_CapsAtThree_HighestSignalFirst()
    {
        var cleaner = CleanerWith(Review(@"C:\a.zip"), Review(@"C:\b.zip"));
        var problems = CollectionResult<DeviceProblemRecord>.Ok(
            [
                new DeviceProblemRecord("id1", "Cam", 28, "Drivers not installed", "bad"),
                new DeviceProblemRecord("id2", "Mic", 10, "Cannot start", "bad"),
            ], "t");
        var detections = CollectionResult<DefenderDetectionRecord>.Ok(
            [new DefenderDetectionRecord("EICAR", 1, "High", "Virus", null, null, null, false)], "t");
        var snap = Snapshot(
            cleaner, problems, detections,
            CollectionResult<EventRecord>.Fail("t", "t"), [], []);

        var findings = OverviewViewModel.BuildFindings(snap);

        Assert.Equal(3, findings.Count);
        Assert.Equal("Storage", findings[0].Module);
        Assert.Equal("Storage", findings[1].Module);
        Assert.Equal("Drivers", findings[2].Module);
    }

    [Fact]
    public void FormatLastScan_ShowsModeAndDuration_OmitsUnknowns()
    {
        var full = new ScanRunInfo(1, 7, @"C:\Docs", "Completed", null, 4102, 9, 100, 12400, 0,
            DateTime.UtcNow.ToString("O"), "Balanced");
        string line = OverviewViewModel.FormatLastScan(full);

        Assert.StartsWith("Last scan: ", line);
        Assert.Contains("Balanced", line);
        Assert.Contains("12.4s", line);

        var bare = new ScanRunInfo(1, 7, @"C:\Docs", "Completed", null, 1, 1, 0, 0, 0,
            DateTime.UtcNow.ToString("O"), "Unknown");
        string bareLine = OverviewViewModel.FormatLastScan(bare);

        Assert.DoesNotContain("Unknown", bareLine);
        Assert.DoesNotContain("0.0s", bareLine);
    }

    [Fact]
    public void BuildActivity_ShowsGeneration_AndSeparatesAi()
    {
        var run = new ScanRunInfo(1, 7, @"C:\Docs", "Completed", null, 10, 10, 0, 1000, 0,
            DateTime.UtcNow.AddHours(-2).ToString("O"), "Balanced");
        var inv = new InvestigationState(
            "inv-1", "scan", "Find disk hogs", "Done", null, 1, 1, 5, 100, 5.0,
            10, 20, 30, 0, 500, false, null, "[]",
            DateTime.UtcNow.AddHours(-1).ToString("O"), "fp");

        var rows = OverviewViewModel.BuildActivity([run], [inv]);

        Assert.Equal(2, rows.Count);
        Assert.Contains("generation 7", rows[1].Detail);
        Assert.Equal("Investigation done", rows[0].Title);
        Assert.Contains("disk hogs", rows[0].Detail);
    }

    [Fact]
    public void GraphZoom_Clamps_AndCommandsStep()
    {
        var vm = Panel();

        vm.GraphZoom = 0.1;
        Assert.Equal(0.5, vm.GraphZoom);
        vm.GraphZoom = 5.0;
        Assert.Equal(2.0, vm.GraphZoom);

        vm.GraphZoom = 1.0;
        vm.ZoomInCommand.Execute(null);
        Assert.Equal(1.25, vm.GraphZoom);
        vm.ZoomOutCommand.Execute(null);
        Assert.Equal(1.0, vm.GraphZoom, precision: 9);
        vm.ZoomInCommand.Execute(null);
        vm.ZoomResetCommand.Execute(null);
        Assert.Equal(1.0, vm.GraphZoom);
    }

    [Fact]
    public void InspectCluster_SetsDetail_WithHonestLabel()
    {
        var vm = Panel();
        var cluster = new RelationCluster("DISK 2", "Disk 2 · 1 GB", 4, "Event 153", true);

        vm.InspectClusterCommand.Execute(cluster);

        Assert.True(vm.HasSelectedCluster);
        Assert.Contains("DISK 2", vm.SelectedClusterDetail);
        Assert.Contains("possible relationship, not a diagnosis", vm.SelectedClusterDetail);

        vm.InspectClusterCommand.Execute("not a cluster");
        Assert.Same(cluster, vm.SelectedCluster);
    }

    [Fact]
    public void Apply_ClearsInspection()
    {
        var vm = Panel();
        vm.InspectClusterCommand.Execute(new RelationCluster("D", "d", 1, "n", false));
        Assert.True(vm.HasSelectedCluster);

        vm.Apply(Snapshot(
            null,
            CollectionResult<DeviceProblemRecord>.Fail("t", "t"),
            CollectionResult<DefenderDetectionRecord>.Fail("t", "t"),
            CollectionResult<EventRecord>.Fail("t", "t"), [], []));

        Assert.False(vm.HasSelectedCluster);
        Assert.Equal(string.Empty, vm.SelectedClusterDetail);
    }

    [Fact]
    public void OpenPageCommand_RoutesPlainAndScopedLinks()
    {
        var vm = Panel();
        int plain = -1;
        int scopedPage = -1;
        string scopedScope = string.Empty;
        vm.NavigateToPage = i => plain = i;
        vm.NavigateWithScope += (page, scope) => { scopedPage = page; scopedScope = scope; };

        vm.OpenPageCommand.Execute(5);
        Assert.Equal(5, plain);
        vm.OpenPageCommand.Execute("5");
        Assert.Equal(5, plain);
        vm.OpenPageCommand.Execute("5|DISK 2");
        Assert.Equal(5, scopedPage);
        Assert.Equal("DISK 2", scopedScope);

        plain = -1;
        scopedPage = -1;
        vm.OpenPageCommand.Execute("junk");
        vm.OpenPageCommand.Execute("5|");
        vm.OpenPageCommand.Execute("|scope");
        Assert.Equal(-1, plain);
        Assert.Equal(-1, scopedPage);
    }

    [Fact]
    public void Crashes_DeepLinkNote()
    {
        var vm = new CrashesViewModel();

        Assert.Equal(string.Empty, vm.DeepLinkNote);
        Assert.False(vm.HasDeepLinkNote);

        vm.DeepLinkNote = "From Overview: DISK 2";

        Assert.True(vm.HasDeepLinkNote);
    }
}
