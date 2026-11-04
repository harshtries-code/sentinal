using Sentinel.App.ViewModels;
using Sentinel.Store;

namespace Sentinel.Tests;

// T55: complete technician reports — actions/photo/sections,
// user-selected findings, persistent library, hostile-data
// escaping, privacy pins. File share only: nothing here
// uploads anything, and there is no PDF.
public sealed class TechnicianReportTests : IDisposable
{
    private readonly string _dir;

    public TechnicianReportTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "sentinel-t55-" + Guid.NewGuid().ToString("N"));
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

    private static ReportsViewModel.TechnicianReport Draft(
        string[]? issues = null,
        string[]? actions = null,
        ReportsViewModel.SectionCoverage[]? sections = null,
        int excluded = 0) =>
        new("today", DateTime.UtcNow, "PC", "Win", "1", "C:", "ok",
            "storage", ["C: — 1 GB used"], "drivers", 3, ["D — Code 1"],
            "prot", "prot detail", 1, "0", "stable", "none", "1",
            issues ?? ["Issue A", "Issue B"],
            sections ?? [new("Storage", "C:", "now", "full")],
            actions ?? ["today · clean_items_to_vault · user · undo: Done"],
            "last 1 audit entry (newest first)",
            "no photos",
            excluded);

    private ReportsViewModel Vm(string? auditDb = null) =>
        new(() => null!,
            auditDb is null ? null : () => new ActionAuditLog(auditDb, "t", "m", "p"),
            new ReportLibrary(Path.Combine(_dir, "lib-" + Guid.NewGuid().ToString("N"))));

    private static long SeedAudit(string path, string action, string undo = "Done")
    {
        using var log = new ActionAuditLog(path, "t", "m", "p");
        return log.Append(DateTime.UtcNow.ToString("o"), "user", action, "[\"f:1\"]",
            null, string.Empty, "{}", "Vault:V-1", undo, "detail");
    }

    // ---- library ----

    [Fact]
    public void Library_Save_List_Load_RoundTrip()
    {
        var library = new ReportLibrary(Path.Combine(_dir, "lib"));

        var entry = library.Save("""{"a":1}""");

        Assert.StartsWith("report-", entry.FileName);
        Assert.Single(library.List());
        Assert.Equal("""{"a":1}""", library.Load(entry.FileName));
    }

    [Theory]
    [InlineData("../evil.json")]
    [InlineData("..\\evil.json")]
    [InlineData("C:\\Windows\\x.json")]
    [InlineData("notes.txt")]
    [InlineData("other-1.json")]
    [InlineData("")]
    public void Library_Load_Rejects_Trickery(string name)
    {
        var library = new ReportLibrary(Path.Combine(_dir, "lib"));

        Assert.Null(library.Load(name));
    }

    [Fact]
    public void Library_Load_Missing_And_Corrupt_Return_Null()
    {
        string dir = Path.Combine(_dir, "lib");
        var library = new ReportLibrary(dir);

        Assert.Null(library.Load("report-20990101-000000-000.json"));
        File.WriteAllText(Path.Combine(dir, "report-bad.json"), "not json {{{");
        Assert.Null(library.Load("report-bad.json"));
    }

    [Fact]
    public void Library_List_Caps_And_Ignores_Foreign_Files()
    {
        string dir = Path.Combine(_dir, "lib");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "notes.txt"), "x");
        for (int i = 0; i < 105; i++)
        {
            File.WriteAllText(Path.Combine(dir, $"report-20260101-000000-{i:000}.json"), "{}");
        }

        var entries = new ReportLibrary(dir).List();

        Assert.Equal(100, entries.Count);
        Assert.All(entries, e => Assert.StartsWith("report-", e.FileName));
    }

    // ---- selections ----

    [Fact]
    public void Apply_Builds_AllIncluded_Selections()
    {
        var vm = Vm();
        vm.Apply(Draft(["A", "B"]));

        Assert.Equal(2, vm.FindingSelections.Count);
        Assert.All(vm.FindingSelections, f => Assert.True(f.Included));
    }

    [Fact]
    public void Uncheck_Reissues_Draft_Without_Finding()
    {
        var vm = Vm();
        vm.Apply(Draft(["Keep me", "Drop me"]));

        vm.FindingSelections[1].Included = false;

        Assert.NotNull(vm.Draft);
        Assert.Equal(["Keep me"], vm.Draft.OpenIssues);
        Assert.Equal(1, vm.Draft.ExcludedFindings);
        Assert.DoesNotContain("Drop me", vm.Preview);
        Assert.Contains("Keep me", vm.Preview);

        vm.FindingSelections[1].Included = true;

        Assert.NotNull(vm.Draft);
        Assert.Equal(2, vm.Draft.OpenIssues.Count);
        Assert.Equal(0, vm.Draft.ExcludedFindings);
    }

    // ---- save / reopen / re-export ----

    [Fact]
    public void Save_Then_Reopen_Restores_Draft()
    {
        var vm = Vm();
        vm.Apply(Draft(["Saved issue"]));

        vm.SaveDraft();

        Assert.Single(vm.SavedReports);
        Assert.NotNull(vm.SelectedSaved);
        Assert.Contains("Saved report-", vm.LibraryNote);

        vm.Apply(Draft(["Different"]));
        vm.ReopenSelected();

        Assert.NotNull(vm.Draft);
        Assert.Equal(["Saved issue"], vm.Draft.OpenIssues);
        Assert.StartsWith("Reopened report-", vm.DraftState);
    }

    [Fact]
    public void Reopen_Corrupt_Reports_Honestly()
    {
        string dir = Path.Combine(_dir, "corrupt-lib");
        var vm = new ReportsViewModel(() => null!, null, new ReportLibrary(dir));
        vm.Apply(Draft(["A"]));
        vm.SaveDraft();
        Assert.NotNull(vm.SelectedSaved);

        File.WriteAllText(Path.Combine(dir, vm.SelectedSaved.FileName), "{{{ not json");

        vm.ReopenSelected();

        Assert.Contains("Could not read", vm.LibraryNote);
        // The current draft is untouched by the failed reopen.
        Assert.NotNull(vm.Draft);
        Assert.Equal(["A"], vm.Draft.OpenIssues);
    }

    [Fact]
    public void Reexport_Writes_Preview_Bytes()
    {
        var vm = Vm();
        vm.Apply(Draft(["A"]));
        vm.SaveDraft();
        vm.Apply(Draft(["B"]));
        vm.ReopenSelected();

        string path = Path.Combine(_dir, "reexport.html");
        Assert.True(vm.WriteExport(path));

        Assert.Equal(vm.Preview, File.ReadAllText(path));
        Assert.Contains(">A<", File.ReadAllText(path));
        Assert.DoesNotContain(">B<", File.ReadAllText(path));
    }

    // ---- formats, escaping, privacy ----

    [Fact]
    public void ExportFormat_Rejects_NonFormats_NoPdf()
    {
        var vm = Vm();
        vm.Apply(Draft(["A"]));

        vm.ExportFormat = "PDF";

        Assert.Equal("HTML", vm.ExportFormat);
        vm.ExportFormat = "JSON";
        Assert.Equal("JSON", vm.ExportFormat);
        vm.ExportFormat = "pdf";
        Assert.Equal("JSON", vm.ExportFormat);
    }

    [Fact]
    public void Html_Contains_New_Sections_And_Escapes_Hostile_Data()
    {
        var vm = Vm();
        vm.Apply(Draft(
            ["<script>alert(1)</script>"],
            ["<b>bold</b> action"],
            [new("Threats", "Defender <state>", "now", "1 & 2")]));

        string html = vm.BuildReportHtml();

        Assert.Contains("Recent actions", html);
        Assert.Contains("Photos", html);
        Assert.Contains("Section coverage", html);
        Assert.DoesNotContain("<script>", html);
        Assert.Contains("&lt;script&gt;", html);
        Assert.Contains("&lt;b&gt;bold&lt;/b&gt;", html);
        Assert.Contains("Defender &lt;state&gt;", html);
        Assert.Contains("1 &amp; 2", html);
    }

    [Fact]
    public void Json_Carries_Sections_And_Excluded_Count()
    {
        var vm = Vm();
        vm.Apply(Draft(["A", "B"]));
        vm.FindingSelections[0].Included = false;

        string json = vm.BuildReportJson();

        Assert.Contains("\"Sections\"", json);
        Assert.Contains("\"ExcludedFindings\":1", json.Replace(" ", string.Empty));
    }

    [Fact]
    public void Report_Carries_No_Raw_Content_Fields()
    {
        // Privacy pin: the draft shape has nowhere to put file
        // contents, dumps, samples, passwords, or keys.
        var names = typeof(ReportsViewModel.TechnicianReport).GetProperties()
            .Select(p => p.Name).ToList();

        string[] banned = ["Content", "Dump", "Sample", "Password", "Secret", "Key"];
        foreach (string name in names)
        {
            foreach (string word in banned)
            {
                Assert.DoesNotContain(word, name, StringComparison.OrdinalIgnoreCase);
            }
        }

        var vm = Vm();
        Assert.Contains("file contents", vm.NotInReport);
        Assert.Contains("photos", vm.NotInReport);
    }

    // ---- audit section ----

    [Fact]
    public void Build_Reads_Recent_Audit_Entries()
    {
        string auditDb = Path.Combine(_dir, "audit.db");
        SeedAudit(auditDb, "clean_items_to_vault");
        SeedAudit(auditDb, "defender_scan", "NotApplicable");
        var vm = Vm(auditDb);

        vm.Generate();

        Assert.NotNull(vm.Draft);
        Assert.Equal(2, vm.Draft.ActionLines.Count);
        Assert.Contains("last 2 audit entries", vm.Draft.ActionsCoverage);
        Assert.Contains(vm.Draft.ActionLines, l => l.Contains("clean_items_to_vault"));
        Assert.Contains(vm.Draft.ActionLines, l => l.Contains("defender_scan"));
    }

    [Fact]
    public void Build_Without_Audit_Says_So()
    {
        var vm = Vm();

        vm.Generate();

        Assert.NotNull(vm.Draft);
        Assert.Empty(vm.Draft.ActionLines);
        Assert.Contains("not connected", vm.Draft.ActionsCoverage);
    }

    [Fact]
    public void Build_Emits_All_Section_Coverage()
    {
        var vm = Vm();
        vm.Apply(Draft());

        var built = vm.Draft;
        Assert.NotNull(built);

        // The live Build path emits 8 section rows; the Draft
        // helper path carries whatever it was given (1 here).
        Assert.Single(built.Sections);

        vm.Generate();
        Assert.NotNull(vm.Draft);
        string[] names = vm.Draft.Sections.Select(s => s.Section).ToArray();
        Assert.Equal(
            ["Device", "Storage", "Drivers", "Crashes", "Threats", "Actions", "Open issues", "Photos"],
            names);
        Assert.All(vm.Draft.Sections, s =>
        {
            Assert.False(string.IsNullOrWhiteSpace(s.Scope));
            Assert.False(string.IsNullOrWhiteSpace(s.At));
            Assert.False(string.IsNullOrWhiteSpace(s.Coverage));
        });
    }
}
