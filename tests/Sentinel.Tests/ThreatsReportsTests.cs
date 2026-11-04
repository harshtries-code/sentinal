using Sentinel.App.ViewModels;

namespace Sentinel.Tests;

// U24/U25: filtered detection timeline + preview/export sharing one
// model and one pair of builders (byte-identical).
public sealed class ThreatsReportsTests : IDisposable
{
    private readonly string _dir;

    public ThreatsReportsTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "sentinel-u24u25-" + Guid.NewGuid().ToString("N"));
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

    private static ThreatDetectionRow Row(string threat, string severity, string path = @"C:\a.exe") =>
        new(threat, severity, path, "today", "Allow", false);

    [Fact]
    public void DetectionFilter_SeverityAndSearch()
    {
        var vm = new ThreatsViewModel();
        vm.Detections.Add(Row("EICAR-Test", "High"));
        vm.Detections.Add(Row("TrackCookie", "Low", @"C:\b.dat"));
        vm.Detections.Add(Row("EICAR-2", "Moderate"));
        vm.ApplyDetectionFilter();

        Assert.Equal(3, vm.FilteredDetections.Count);

        vm.DetectionSeverityFilter = "High";
        Assert.Single(vm.FilteredDetections);

        vm.DetectionSeverityFilter = "All severities";
        vm.DetectionSearch = "eicar";
        Assert.Equal(2, vm.FilteredDetections.Count);

        vm.DetectionSeverityFilter = "Low";
        Assert.Empty(vm.FilteredDetections);

        vm.DetectionSeverityFilter = "All severities";
        vm.DetectionSearch = string.Empty;
        Assert.Equal(3, vm.FilteredDetections.Count);
    }

    [Fact]
    public void DetectionFilter_ClearsSelection_WhenFilteredOut()
    {
        var vm = new ThreatsViewModel();
        var high = Row("EICAR-Test", "High");
        vm.Detections.Add(high);
        vm.Detections.Add(Row("TrackCookie", "Low"));
        vm.ApplyDetectionFilter();
        vm.SelectedDetection = high;

        vm.DetectionSeverityFilter = "Low";

        Assert.Null(vm.SelectedDetection);
        Assert.Single(vm.FilteredDetections);
    }

    private static ReportsViewModel.TechnicianReport Draft(params string[] issues) =>
        new("today", DateTime.UtcNow, "PC", "Win", "1", "C:", "ok",
            "storage", [], "drivers", 0, [], "prot", "prot detail", 0,
            "crashes", "stable", "none", "scans", issues,
            [], [], "audit connected — no actions recorded yet", "no photos", 0);

    [Fact]
    public void Preview_MatchesExportBytes_InBothFormats()
    {
        var vm = new ReportsViewModel(() => null!);
        vm.Apply(Draft("Disk C: is 90% full."));

        Assert.Equal(vm.BuildReportHtml(), vm.Preview);

        vm.ExportFormat = "JSON";
        Assert.Equal(vm.BuildReportJson(), vm.Preview);

        string path = Path.Combine(_dir, "report.json");
        Assert.True(vm.WriteExport(path));
        Assert.Equal(vm.Preview, File.ReadAllText(path));
    }

    [Fact]
    public void Preview_EscapesHostileStrings()
    {
        var vm = new ReportsViewModel(() => null!);
        vm.Apply(Draft("<script>x</script>", "A&B"));

        Assert.DoesNotContain("<script>x</script>", vm.Preview);
        Assert.Contains("&lt;script&gt;", vm.Preview);
        Assert.Contains("A&amp;B", vm.Preview);
    }

    [Fact]
    public void ExportFormat_WithoutDraft_KeepsPlaceholder()
    {
        var vm = new ReportsViewModel(() => null!);
        string before = vm.Preview;

        vm.ExportFormat = "JSON";

        Assert.Equal(before, vm.Preview);
        Assert.False(vm.HasDraft);
    }
}
