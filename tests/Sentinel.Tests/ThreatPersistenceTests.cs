using Sentinel.App.ViewModels;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.Tests;

// T51: the rest of the persistence map (scheduled tasks,
// browser-extension manifests, WMI subscriptions) plus
// process-parent and TCP-connection topography.
public sealed class ThreatPersistenceTests : IDisposable
{
    private readonly string _dir;

    public ThreatPersistenceTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "sentinel-t51-" + Guid.NewGuid().ToString("N"));
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

    // ---- scheduled tasks ----

    [Fact]
    public void TaskCsv_Parses_Quoted_Comma_Names()
    {
        var (records, unparsed) = ScheduledTaskCollector.ParseCsv(
            "\"\\My, Task\",\"1/1/2026 9:00 AM\",\"Ready\",\"Interactive\"",
            ScheduledTaskCollector.MaxTasks);

        Assert.Equal(0, unparsed);
        var only = Assert.Single(records);
        Assert.Equal("\\My, Task", only.TaskName);
        Assert.Equal("Ready", only.Status);
        Assert.Equal("Interactive", only.LogonMode);
    }

    [Fact]
    public void TaskCsv_Skips_Blank_And_Short_Lines()
    {
        var (records, unparsed) = ScheduledTaskCollector.ParseCsv(
            "\n\"only\",\"two\"\n\"\\T\",\"\",\"Running\"",
            ScheduledTaskCollector.MaxTasks);

        Assert.Equal(1, unparsed);
        Assert.Single(records);
    }

    [Fact]
    public void TaskCsv_Respects_Limit()
    {
        var (records, _) = ScheduledTaskCollector.ParseCsv(
            "\"\\A\",\"\",\"Ready\"\n\"\\B\",\"\",\"Ready\"\n\"\\C\",\"\",\"Ready\"", 2);

        Assert.Equal(2, records.Count);
    }

    [Fact]
    public void TaskCollect_Fixture_Output_Succeeds()
    {
        var result = ScheduledTaskCollector.Collect(
            () => "\"\\T\",\"\",\"Ready\",\"System\"");

        Assert.Equal(CollectionStatus.Success, result.Status);
        Assert.Single(result.Records);
    }

    [Fact]
    public void TaskCollect_Reader_Throws_Fails()
    {
        var result = ScheduledTaskCollector.Collect(
            () => throw new InvalidOperationException("no schtasks"));

        Assert.NotEqual(CollectionStatus.Success, result.Status);
        Assert.Empty(result.Records);
    }

    private const string SampleTaskXml = """
        <?xml version="1.0" encoding="UTF-16"?>
        <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <RegistrationInfo><Author>ACME\user</Author></RegistrationInfo>
          <Triggers>
            <LogonTrigger><StartBoundary>2026-01-01T09:00:00</StartBoundary></LogonTrigger>
            <TimeTrigger><Enabled>false</Enabled></TimeTrigger>
          </Triggers>
          <Actions>
            <Exec><Command>C:\tools\run.exe</Command><Arguments>/quiet</Arguments></Exec>
            <ComHandler><ClassId>{00000000-0000-0000-0000-000000000000}</ClassId></ComHandler>
          </Actions>
          <Settings><Hidden>true</Hidden></Settings>
        </Task>
        """;

    [Fact]
    public void TaskXml_Parses_Actions_Triggers_Hidden()
    {
        var detail = ScheduledTaskCollector.ParseXml(SampleTaskXml, "\\T");

        Assert.NotNull(detail);
        Assert.Equal("\\T", detail.TaskName);
        Assert.Contains(@"C:\tools\run.exe /quiet", detail.Actions);
        Assert.Contains("COM handler {00000000-0000-0000-0000-000000000000}", detail.Actions);
        Assert.Contains("LogonTrigger @ 2026-01-01T09:00:00", detail.Triggers);
        Assert.Contains("TimeTrigger (disabled)", detail.Triggers);
        Assert.Equal("ACME\\user", detail.Author);
        Assert.True(detail.Hidden);
    }

    [Fact]
    public void TaskXml_Invalid_Or_Blank_Returns_Null()
    {
        Assert.Null(ScheduledTaskCollector.ParseXml("not xml", "\\T"));
        Assert.Null(ScheduledTaskCollector.ParseXml("   ", "\\T"));
    }

    [Fact]
    public void ReadDetail_Blank_Returns_Null()
    {
        Assert.Null(ScheduledTaskCollector.ReadDetail("  "));
    }

    // ---- browser extensions ----

    private const string SampleManifest = """
        {
          "name": "Sample Ext",
          "version": "1.2.3",
          "permissions": ["storage", "tabs"],
          "host_permissions": ["https://example.com/*"],
          "content_scripts": [{"matches": ["<all_urls>"], "js": ["c.js"]}]
        }
        """;

    [Fact]
    public void Manifest_Parses_Mv3_With_ContentScripts()
    {
        var record = BrowserExtensionCollector.ParseManifest(
            "Chrome", "Default", "id1", SampleManifest, @"C:\m\manifest.json");

        Assert.NotNull(record);
        Assert.Equal("Sample Ext", record.Name);
        Assert.Equal("1.2.3", record.Version);
        Assert.Contains("storage", record.Permissions);
        Assert.Contains("host:https://example.com/*", record.Permissions);
        Assert.True(record.HasContentScripts);
    }

    [Fact]
    public void Manifest_MsgName_Falls_Back_To_Id()
    {
        var record = BrowserExtensionCollector.ParseManifest(
            "Edge", "Default", "id2", """{"name":"__MSG_appName__","version":"2"}""",
            @"C:\m\manifest.json");

        Assert.NotNull(record);
        Assert.Equal("id2", record.Name);
        Assert.False(record.HasContentScripts);
    }

    [Fact]
    public void Manifest_Invalid_Returns_Null()
    {
        Assert.Null(BrowserExtensionCollector.ParseManifest(
            "Chrome", "Default", "id", "nope", @"C:\m\manifest.json"));
        Assert.Null(BrowserExtensionCollector.ParseManifest(
            "Chrome", "Default", "id", "[1,2]", @"C:\m\manifest.json"));
    }

    [Fact]
    public void Manifest_Permissions_Capped_At_20()
    {
        string json = """{"name":"P","version":"1","permissions":["""
            + string.Join(",", Enumerable.Range(0, 25).Select(i => $"\"p{i}\""))
            + "]}";
        var record = BrowserExtensionCollector.ParseManifest(
            "Chrome", "Default", "id", json, @"C:\m\manifest.json");

        Assert.NotNull(record);
        Assert.Equal(20, record.Permissions.Count);
    }

    [Fact]
    public void Firefox_Addon_Parses_Registry_Only()
    {
        using var doc = System.Text.Json.JsonDocument.Parse(
            """{"id":"addon@x","version":"4.5"}""");
        var record = BrowserExtensionCollector.ParseFirefoxAddon(
            "prof1", Path.Combine(_dir, "prof1"), doc.RootElement);

        Assert.NotNull(record);
        Assert.Equal("Firefox", record.Browser);
        Assert.Equal("addon@x", record.Id);
        Assert.Equal("4.5", record.Version);
        Assert.Equal("(registry only)", record.ManifestPath);
    }

    [Fact]
    public void Firefox_Addon_Missing_Id_Returns_Null()
    {
        using var doc = System.Text.Json.JsonDocument.Parse("""{"version":"1"}""");
        Assert.Null(BrowserExtensionCollector.ParseFirefoxAddon(
            "prof1", Path.Combine(_dir, "prof1"), doc.RootElement));
    }

    [Fact]
    public void ExtensionCollect_FixtureDir_Finds_Manifest()
    {
        string extDir = Path.Combine(_dir, "local",
            @"Google\Chrome\User Data\Default\Extensions\testid\1.0");
        Directory.CreateDirectory(extDir);
        File.WriteAllText(Path.Combine(extDir, "manifest.json"), SampleManifest);

        var result = BrowserExtensionCollector.Collect(
            Path.Combine(_dir, "local"), Path.Combine(_dir, "roaming"));

        Assert.Equal(CollectionStatus.Success, result.Status);
        var only = Assert.Single(result.Records);
        Assert.Equal("Sample Ext", only.Name);
        Assert.Equal("Chrome", only.Browser);
    }

    [Fact]
    public void ExtensionCollect_MissingDirs_Succeeds_Empty()
    {
        var result = BrowserExtensionCollector.Collect(
            Path.Combine(_dir, "no-local"), Path.Combine(_dir, "no-roaming"));

        Assert.Equal(CollectionStatus.Success, result.Status);
        Assert.Empty(result.Records);
    }

    [Fact]
    public void ExtensionCollect_Only_Opens_Manifest_Or_Registry()
    {
        // The collector's metadata-only promise: every opened path
        // ends in manifest.json, extensions.json, a signed .xpi
        // (manifest entry only), or is an honest registry-only row.
        string extDir = Path.Combine(_dir, "pin",
            @"Microsoft\Edge\User Data\Default\Extensions\eid\2.0");
        Directory.CreateDirectory(extDir);
        File.WriteAllText(Path.Combine(extDir, "manifest.json"), SampleManifest);
        string ffProfile = Path.Combine(_dir, "pin-roam", @"Mozilla\Firefox\Profiles\prof1");
        Directory.CreateDirectory(ffProfile);
        File.WriteAllText(Path.Combine(ffProfile, "extensions.json"),
            """{"addons":[{"id":"a@x","version":"1"}]}""");

        var result = BrowserExtensionCollector.Collect(
            Path.Combine(_dir, "pin"), Path.Combine(_dir, "pin-roam"));

        Assert.Equal(2, result.Records.Count);
        foreach (var record in result.Records)
        {
            Assert.True(
                record.ManifestPath.EndsWith("manifest.json", StringComparison.OrdinalIgnoreCase)
                || record.ManifestPath.EndsWith("extensions.json", StringComparison.OrdinalIgnoreCase)
                || record.ManifestPath.EndsWith(".xpi", StringComparison.OrdinalIgnoreCase)
                || record.ManifestPath == "(registry only)",
                $"unexpected opened path: {record.ManifestPath}");
        }
    }

    // ---- WMI persistence ----

    [Fact]
    public void MapFilter_Maps_Name_Query()
    {
        var filter = WmiPersistenceCollector.MapFilter(
            new Dictionary<string, object?>
            {
                ["Name"] = "MyFilter",
                ["Query"] = "SELECT * FROM __InstanceModificationEvent",
                ["QueryLanguage"] = "WQL",
            });

        Assert.Equal("MyFilter", filter.Name);
        Assert.Contains("__InstanceModificationEvent", filter.Query);
        Assert.Equal("WQL", filter.QueryLanguage);
    }

    [Fact]
    public void MapBinding_Maps_Filter_Consumer()
    {
        var binding = WmiPersistenceCollector.MapBinding(
            new Dictionary<string, object?>
            {
                ["Filter"] = "F1",
                ["Consumer"] = "C1",
            });

        Assert.Equal("F1", binding.Filter);
        Assert.Equal("C1", binding.Consumer);
    }

    [Fact]
    public void WmiCollect_Live_Completes()
    {
        // Read-only live read: completes on host; a missing
        // namespace fails closed with a gap, never an exception.
        var result = WmiPersistenceCollector.Collect();

        Assert.NotNull(result.Records);
        if (result.Status != CollectionStatus.Success)
        {
            Assert.NotEmpty(result.Gaps);
        }
    }

    // ---- process parents + network ----

    [Fact]
    public void ProcessCollect_Self_Has_Parent()
    {
        var result = ProcessCollector.Collect();
        var self = result.Records.FirstOrDefault(p => p.Id == Environment.ProcessId);

        Assert.NotNull(self);
        Assert.NotNull(self.ParentId);
    }

    [Fact]
    public void NetworkCollect_Live_Bounded_Wellformed()
    {
        var result = NetworkCollector.Collect();

        Assert.Equal(CollectionStatus.Success, result.Status);
        Assert.True(result.Records.Count <= NetworkCollector.MaxConnections);
        Assert.All(result.Records, c =>
        {
            Assert.False(string.IsNullOrWhiteSpace(c.Remote));
            Assert.True(c.Pid >= 0);
        });
    }

    [Fact]
    public void TcpTable_Live_Completes()
    {
        var rows = ExtendedTcpTable.Collect();

        Assert.NotNull(rows);
    }

    // ---- Threats surfacing ----

    [Fact]
    public void Apply_Sets_Persistence_Lines()
    {
        var vm = new ThreatsViewModel();
        vm.Apply(new ThreatsViewModel.ThreatsSnapshot(
            "b", "d", "On", "Today", "Today", "c", [], [], [], 1, 2, 3, "n",
            TaskCount: 4, ExtensionCount: 5, WmiCount: 6));

        Assert.Equal("Scheduled task · 4 items", vm.TaskLine);
        Assert.Equal("Browser extension · 5 items", vm.ExtensionLine);
        Assert.Equal("WMI subscription · 6 items", vm.WmiLine);
    }

    [Fact]
    public void ProcessDetail_Signed_With_Connections()
    {
        var vm = new ThreatsViewModel();
        vm.SelectedProcess = new ThreatProcessRow("a.exe (PID 1)", @"C:\a.exe", "Co", "1 MB", "p", 1);
        var record = new StaticFileEvidenceRecord(
            @"C:\a.exe", true, 10, "ABC", true, "Subj", "Iss", null);
        var connections = new List<TcpConnectionRecord>
        {
            new(1, "127.0.0.1:1", "93.184.216.34:443", "Established"),
        };

        vm.SetProcessDetail(vm.BeginProcessDetail(), 1, record, connections);

        Assert.Contains("Subj", vm.ProcessDetailLine);
        Assert.Contains("93.184.216.34:443", vm.ProcessDetailLine);
    }

    [Fact]
    public void ProcessDetail_Unsigned_Warns()
    {
        var vm = new ThreatsViewModel();
        vm.SelectedProcess = new ThreatProcessRow("a.exe (PID 1)", @"C:\a.exe", "?", "1 MB", "p", 1);
        var record = new StaticFileEvidenceRecord(
            @"C:\a.exe", true, 10, "ABC", false, null, null, null);

        vm.SetProcessDetail(vm.BeginProcessDetail(), 1, record, []);

        Assert.Contains("Unsigned", vm.ProcessDetailLine);
        Assert.Contains("No network connections observed", vm.ProcessDetailLine);
    }

    [Fact]
    public void ProcessDetail_Stale_Token_Dropped()
    {
        var vm = new ThreatsViewModel();
        vm.SelectedProcess = new ThreatProcessRow("a.exe (PID 1)", @"C:\a.exe", "?", "1 MB", "p", 1);
        long stale = vm.BeginProcessDetail();
        vm.Apply(new ThreatsViewModel.ThreatsSnapshot(
            "b", "d", "On", "Today", "Today", "c", [], [], [], 0, 0, 0, "n"));

        vm.SetProcessDetail(stale, 1, null, []);

        Assert.Null(vm.ProcessDetailLine);
    }

    [Fact]
    public void PersistenceDetail_Hidden_Task_Flags()
    {
        var vm = new ThreatsViewModel();
        var row = new PersistenceRow("Scheduled task", "\\T", "Ready");
        vm.SelectedPersistence = row;
        var detail = new ScheduledTaskDetail(
            "\\T", [@"C:\t.exe"], ["LogonTrigger"], null, Hidden: true);

        vm.SetPersistenceDetail(vm.BeginPersistenceDetail(), row, detail, null);

        Assert.Contains("C:\\t.exe", vm.PersistenceDetailLine);
        Assert.Contains("H-task-hidden", vm.PersistenceDetailLine);
    }

    [Fact]
    public void PersistenceDetail_Null_Detail_Fails_Honestly()
    {
        var vm = new ThreatsViewModel();
        var row = new PersistenceRow("Scheduled task", "\\T", "Ready");
        vm.SelectedPersistence = row;

        vm.SetPersistenceDetail(vm.BeginPersistenceDetail(), row, null, " elevation needed ");

        Assert.Contains("elevation needed", vm.PersistenceDetailLine);
    }

    [Fact]
    public void PersistenceSummary_Echoes_Suspicion()
    {
        var vm = new ThreatsViewModel();
        vm.ShowPersistenceSummary(new PersistenceRow(
            "Browser extension", "E", "Chrome", ThreatsViewModel.SuspicionExtensionContent));

        Assert.Contains("H-ext-content", vm.PersistenceDetailLine);
    }

    [Fact]
    public void Suspicion_Vocabulary_Never_Names_Malware()
    {
        string[] notes =
        [
            ThreatsViewModel.SuspicionExtensionContent,
            ThreatsViewModel.SuspicionWmiBinding,
            ThreatsViewModel.SuspicionTaskHidden,
        ];
        string[] banned = ["malware", "virus", "trojan", "infected", "malicious"];

        foreach (string note in notes)
        {
            Assert.StartsWith("H-", note);
            foreach (string word in banned)
            {
                Assert.DoesNotContain(word, note, StringComparison.OrdinalIgnoreCase);
            }
        }
    }
}
