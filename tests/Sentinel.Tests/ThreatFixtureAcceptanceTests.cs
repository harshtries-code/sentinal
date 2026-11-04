using Sentinel.App.ViewModels;
using Sentinel.Engine.Actions;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.Tests;

// T54: false-positive + harmless-fixture acceptance. Benign
// files with scary names (miner-like), game-like large unsigned
// files, and synthetic miner-ish signals must surface as
// UNVERIFIED with check-first notes — never a malware verdict,
// never a deletion recommendation. No real malware anywhere:
// fixtures are benign bytes written by the test itself.
public sealed class ThreatFixtureAcceptanceTests : IDisposable
{
    private readonly string _dir;

    public ThreatFixtureAcceptanceTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "sentinel-t54-" + Guid.NewGuid().ToString("N"));
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

    private string WriteFixture(string name, int bytes)
    {
        // Benign content, miner-evocative name on purpose: the
        // acceptance is that scary names change nothing.
        string path = Path.Combine(_dir, name);
        var content = new byte[bytes];
        for (int i = 0; i < content.Length; i++)
        {
            content[i] = (byte)('A' + (i % 26));
        }

        File.WriteAllBytes(path, content);
        return path;
    }

    private static StaticFileEvidenceRecord CheckOne(string path)
    {
        var result = StaticEvidenceCollector.CheckFiles([path], 1);
        Assert.Equal(CollectionStatus.Success, result.Status);
        return Assert.Single(result.Records);
    }

    private static void AssertNoVerdict(string text)
    {
        string[] banned =
        [
            "malware", "virus", "trojan", "infected", "malicious",
            "delete", "uninstall", "get rid of", "you should remove",
        ];
        foreach (string word in banned)
        {
            Assert.DoesNotContain(word, text, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void FakeMinerNamed_File_Stays_Unverified()
    {
        string path = WriteFixture("coinminer-simulator-fixture.bin", 2048);
        var record = CheckOne(path);

        Assert.False(record.Signed);
        string text = ThreatsViewModel.ExplainFileEvidence(record);

        Assert.Contains("treat with care", text);
        AssertNoVerdict(text);
    }

    [Fact]
    public void GameLike_Large_Unsigned_File_Stays_Unverified()
    {
        string path = WriteFixture("game-like-big-mod-fixture.bin", 1024 * 1024);
        var record = CheckOne(path);

        Assert.False(record.Signed);
        Assert.NotNull(record.Sha256);
        string text = ThreatsViewModel.ExplainFileEvidence(record);

        Assert.Contains("freshly built", text);
        AssertNoVerdict(text);
    }

    [Fact]
    public void Known_Signed_System_File_Explains_Origin()
    {
        // Whatever this machine says about its own cmd.exe, the
        // explanation is evidence-shaped, never a verdict.
        string cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        if (!File.Exists(cmd))
        {
            Assert.Fail("cmd.exe missing — not a Windows host?");
        }

        string text = ThreatsViewModel.ExplainFileEvidence(CheckOne(cmd));

        Assert.True(
            text.Contains("Verified signature", StringComparison.Ordinal) ||
            text.Contains("No verified signature", StringComparison.Ordinal));
        AssertNoVerdict(text);
    }

    [Fact]
    public void MinerLike_Process_Signal_Unverified_With_Parent_And_Company_Notes()
    {
        // The row shape Collect builds for an unknown-company
        // process: check-first company, parent line, no verdict.
        var row = new ThreatProcessRow(
            "xmrig-sim (PID 4242)", Path.Combine(_dir, "coinminer-simulator-fixture.bin"),
            "Unknown company — check first", "12 MB", "services.exe (PID 600)", 4242);

        AssertNoVerdict(row.Name + " " + row.Company + " " + row.Parent);

        var vm = new ThreatsViewModel();
        vm.SelectedProcess = row;
        vm.SetProcessDetail(vm.BeginProcessDetail(), 4242,
            new StaticFileEvidenceRecord(row.Path, true, 2048, "ABC",
                false, null, null, null),
            []);

        Assert.NotNull(vm.ProcessDetailLine);
        Assert.Contains("Unsigned", vm.ProcessDetailLine);
        AssertNoVerdict(vm.ProcessDetailLine);
    }

    [Fact]
    public void MinerLike_Task_Signal_Lists_Without_Verdict()
    {
        var row = new PersistenceRow(
            "Scheduled task", "\\SentinelFixture\\coinminer-sim", "Ready");

        Assert.Equal(string.Empty, row.Suspicion);
        AssertNoVerdict(row.Type + " " + row.Name + " " + row.Detail);

        var vm = new ThreatsViewModel();
        vm.SelectedPersistence = row;
        vm.SetPersistenceDetail(vm.BeginPersistenceDetail(), row,
            new ScheduledTaskDetail("\\SentinelFixture\\coinminer-sim",
                [@"C:\fixtures\miner-sim.bat"], ["LogonTrigger"], null, Hidden: false),
            null);

        Assert.NotNull(vm.PersistenceDetailLine);
        Assert.Contains("Runs:", vm.PersistenceDetailLine);
        AssertNoVerdict(vm.PersistenceDetailLine);
    }

    [Fact]
    public void Suspicion_Notes_Carry_No_Recommendations()
    {
        string[] notes =
        [
            ThreatsViewModel.SuspicionExtensionContent,
            ThreatsViewModel.SuspicionWmiBinding,
            ThreatsViewModel.SuspicionTaskHidden,
            "Unknown company — check first",
            "Unsigned — treat with care.",
        ];

        foreach (string note in notes)
        {
            AssertNoVerdict(note);
        }
    }

    [Fact]
    public void Quarantine_Demo_Fixture_Explains_And_Plans()
    {
        // T52 is lawful + supported, so T54 demonstrates it on a
        // fixture: explanation + exact plan. NO execution here —
        // the live round-trip is the VM battery's job.
        var history = new List<DefenderDetectionRecord>
        {
            new("TestFixture:Win32/Sentinel", 1, "High", "Test",
                @"E:\fixtures\demo.bin",
                new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc),
                "Quarantined", false),
        };
        var listed = new QuarantineRecord(
            "TestFixture:Win32/Sentinel", "TestFixture:Win32/Sentinel",
            @"E:\fixtures\demo.bin", "listed", "Name: TestFixture:Win32/Sentinel");

        string explanation = ThreatsViewModel.ExplainQuarantine(listed, history);
        Assert.Contains("High", explanation);
        Assert.Contains("Quarantined", explanation);

        var plan = QuarantineRestore.Plan(new QuarantineRestoreRequest(listed.Name));
        Assert.True(plan.Ready);
        Assert.Contains("-Restore -Name \"TestFixture:Win32/Sentinel\"", plan.CommandLine);

        var template = ActionRegistry.All.First(t => t.Id == "quarantine_restore");
        var sheet = new QuarantineSheetViewModel(plan, explanation, template, () => null!);
        Assert.Contains("TestFixture", sheet.TargetLine);
        Assert.Contains("cannot put it back", sheet.ReversibilityLine);
    }

    [Fact]
    public void Requarantine_Requirement_Retained_Not_Claimed()
    {
        // DEC-REQUARANTINE stays open: no supported verb exists,
        // so no successful-flow claim is made here.
        Assert.Equal(TemplateStatus.Proposed,
            ActionRegistry.Find("quarantine_file_via_defender")?.Status);
        Assert.Equal(TemplateStatus.Active,
            ActionRegistry.Find("quarantine_restore")?.Status);
    }
}
