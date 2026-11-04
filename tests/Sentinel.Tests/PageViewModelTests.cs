using System.Text.Json;
using Sentinel.App.Services;
using Sentinel.App.ViewModels;
using Sentinel.Engine.Ask;
using Sentinel.Engine.CrashDoctor;
using Sentinel.Engine.SystemInventory;
using Sentinel.Store;

namespace Sentinel.Tests;

// R4 page tests: every read-only page collects, applies, and stays
// honest (coverage stated, empty states real, exports parseable).
// Live-collector pages assert shape, never fixed data.
public sealed class PageViewModelTests : IDisposable
{
    private readonly string _dir;
    private readonly string _dbPath;
    private readonly string _agentPath;
    private readonly string _settingsPath;
    private bool _disposed;

    public PageViewModelTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "sentinel-r4-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _dbPath = Path.Combine(_dir, "t.db");
        _agentPath = Path.Combine(_dir, "a.db");
        _settingsPath = Path.Combine(_dir, "settings.json");
    }

    private SentinelDb OpenScanDb() => new(_dbPath);

    private AgentStore OpenAgentDb() => new(_agentPath);

    private void SeedFingerprints()
    {
        using var db = OpenScanDb();
        long now = DateTime.UtcNow.Ticks;
        db.UpsertFingerprint(Path.Combine(Path.GetTempPath(), "r4-junk.tmp"), 5000, now, null, 1);
        db.UpsertFingerprint(@"C:\Work\big-old.iso", 2L * 1024 * 1024 * 1024, DateTime.UtcNow.AddDays(-400).Ticks, "H1", 1);
        db.UpsertFingerprint(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "r4-note.txt"),
            100, now, null, 1);
    }

    [Fact]
    public void Cleaner_ClassifiesSeededInventory_WithStatedCoverage()
    {
        SeedFingerprints();
        var vm = new CleanerViewModel(OpenScanDb, () => []);

        vm.Refresh();

        Assert.Contains("3 files", vm.Summary);
        Assert.Contains("all 3", vm.Coverage);
        Assert.Equal(3, vm.Tiers.Count);
        Assert.Contains(vm.Rows, r => r.Tier == "SAFE");
        Assert.Contains(vm.Rows, r => r.Tier == "REVIEW");
        // A02: protected files stay visible but refuse selection (board 02
        // shows Never-touch rows with their classification; audit probe 1).
        var note = Assert.Single(vm.Rows, r => r.Detail.FullPath.EndsWith("r4-note.txt"));
        Assert.Equal("NEVER", note.Tier);
        Assert.False(note.IsSelectable);
        note.IsSelected = true;
        Assert.False(note.IsSelected);
    }

    [Fact]
    public void Cleaner_HonorsNeverList()
    {
        SeedFingerprints();
        string keep = Path.Combine(Path.GetTempPath(), "r4-keep");
        Directory.CreateDirectory(keep);
        string kept = Path.Combine(keep, "a.tmp");
        File.WriteAllBytes(kept, [1]);
        using (var db = OpenScanDb())
        {
            db.UpsertFingerprint(kept, 10, DateTime.UtcNow.Ticks, null, 1);
        }

        var vm = new CleanerViewModel(OpenScanDb, () => [keep]);
        vm.Refresh();

        // A02: the never-list entry stays visible but refuses selection.
        var row = Assert.Single(vm.Rows, r => r.Detail.FullPath == kept);
        Assert.Equal("NEVER", row.Tier);
        Assert.False(row.IsSelectable);
        row.IsSelected = true;
        Assert.False(row.IsSelected);
    }

    [Fact]
    public void Cleaner_CollectApplyFilter_ProtectedVisible_NeverSelectable()
    {
        // A06: the explicit pipeline over real fixture inventory —
        // safe + review + a LARGE never-listed file. All/Never/Large
        // inspection can all show the protected row; no filter path
        // can turn it into a cleanup selection.
        string keep = Path.Combine(Path.GetTempPath(), "sentinel-a06-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(keep);
        string locked = Path.Combine(keep, "big-locked.bin");
        File.WriteAllBytes(locked, [7]);
        long now = DateTime.UtcNow.Ticks;
        using (var db = OpenScanDb())
        {
            db.UpsertFingerprint(Path.Combine(Path.GetTempPath(), "a06-junk.tmp"), 5000, now, null, 1);
            db.UpsertFingerprint(@"C:\Work\big-old.iso", 2L * 1024 * 1024 * 1024, DateTime.UtcNow.AddDays(-400).Ticks, "H1", 1);
            db.UpsertFingerprint(locked, 3L * 1024 * 1024 * 1024, now, null, 1);
        }

        try
        {
            var vm = new CleanerViewModel(OpenScanDb, () => [keep]);
            var snapshot = CleanerViewModel.Collect(OpenScanDb, [keep]);
            vm.Apply(snapshot);

            foreach (string chip in new[] { "All", "Never", "Large" })
            {
                vm.SelectedChip = chip;
                var row = Assert.Single(vm.VisibleRows, r => r.Detail.FullPath == locked);
                Assert.Equal("NEVER", row.Tier);
                Assert.False(row.IsSelectable);
                // Bulk path: try to select everything visible.
                foreach (var visible in vm.VisibleRows)
                {
                    visible.IsSelected = true;
                }

                Assert.DoesNotContain(vm.CheckedRows(), r => r.Detail.FullPath == locked);
                vm.ClearSelection();
            }

            // And the actionable rows still select normally.
            vm.SelectedChip = "All";
            var safe = Assert.Single(vm.VisibleRows, r => r.Tier == "SAFE");
            safe.IsSelected = true;
            Assert.Contains(vm.CheckedRows(), r => r.Tier == "SAFE");
        }
        finally
        {
            Directory.Delete(keep, true);
        }
    }

    [Fact]
    public void Cleaner_EmptyDb_AsksForScan()
    {
        var vm = new CleanerViewModel(OpenScanDb, () => []);
        vm.Refresh();

        Assert.Equal("Not inspected yet.", vm.Summary);
        Assert.Contains("run a scan", vm.Coverage);
    }

    [Theory]
    [InlineData(1, "file", null, "1 file")]
    [InlineData(2, "file", null, "2 files")]
    [InlineData(0, "event", null, "0 events")]
    [InlineData(1, "copy", "copies", "1 copy")]
    [InlineData(3, "copy", "copies", "3 copies")]
    public void CountText_Pluralizes_One_And_Other(long n, string singular, string? plural, string expected)
    {
        Assert.Equal(expected, CountText.Of(n, singular, plural));
    }

    [Fact]
    public void Cleaner_AllProtectedInventory_SaysSo_NotNoInventory()
    {
        using (var db = OpenScanDb())
        {
            db.UpsertFingerprint(
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "r4-sys.dll"),
                1000, DateTime.UtcNow.Ticks, null, 1);
        }

        var vm = new CleanerViewModel(OpenScanDb, () => []);
        vm.Refresh();

        Assert.Contains("1 file", vm.Summary);
        // A02: all-protected inventory shows its rows (marked, unselectable)
        // instead of an empty table.
        var row = Assert.Single(vm.VisibleRows);
        Assert.Equal("NEVER", row.Tier);
        Assert.False(row.IsSelectable);
    }

    // A02 VM: the Storage chips rendered blank because XAML {Binding}
    // cannot see static members. The instance passthrough below is the
    // binding contract — if it is removed or renamed, the chips go
    // blank again with no build error.
    [Fact]
    public void Cleaner_Chips_InstanceBinding_ExposesChipNames()
    {
        var vm = new CleanerViewModel(OpenScanDb, () => []);
        Assert.Equal(CleanerViewModel.ChipNames, vm.Chips);
        Assert.Contains("Never", vm.Chips);
    }

    // Same blank-control class on Performance: the range ComboBox
    // binds {Binding Ranges}, which must resolve to an instance member.
    [Fact]
    public void Performance_Ranges_InstanceBinding_ExposesRangeNames()
    {
        var vm = new PerformanceViewModel();
        Assert.Equal(PerformanceViewModel.RangeNames, vm.Ranges);
        Assert.NotEmpty(vm.Ranges);
    }

    // P22 replaces the subset pipeline (CategorizeFile/FilterRows/
    // list-treemap) with DB queries: chips/search/scope page the
    // stated inventory. These tests pin the new contract end to end
    // through Collect + Apply + chip paging on fixture inventory.
    [Fact]
    public void Storage_Chips_QueryFullInventory_NotASample()
    {
        string bulk = Path.Combine(Path.GetTempPath(), "p22bulk" + Guid.NewGuid().ToString("N"));
        long nowTicks = DateTime.UtcNow.Ticks;
        using (var db = OpenScanDb())
        {
            for (int i = 0; i < 150; i++)
            {
                db.UpsertFingerprint(
                    Path.Combine(bulk, $"file{i:D3}.tmp"), 100 + i, nowTicks, null, 1);
            }

            string keep = Path.Combine(_dir, "keeplist");
            Directory.CreateDirectory(keep);
            for (int i = 0; i < 3; i++)
            {
                db.UpsertFingerprint(
                    Path.Combine(keep, $"k{i}.tmp"), 50, nowTicks, null, 1);
            }
        }

        string keepDir = Path.Combine(_dir, "keeplist");
        var vm = new CleanerViewModel(OpenScanDb, () => [keepDir]);
        vm.Refresh();

        Assert.Contains("153 files", vm.Summary);
        Assert.Contains("all 153", vm.Coverage);
        // First page is bounded; the total is stated, not sampled.
        Assert.Equal(100, vm.VisibleRows.Count);
        Assert.True(vm.HasNextPage);
        Assert.False(vm.HasPrevPage);
        Assert.Contains("1–100 of 153", vm.PageLabel);
        // Tier chips query the same inventory (never-list is exact).
        vm.SelectedChip = "Never";
        Assert.Equal(3, vm.VisibleRows.Count);
        Assert.Contains("of 3", vm.PageLabel);
        // Search composes with the chip over the full set.
        vm.SelectedChip = "All";
        vm.SearchText = "file1";
        Assert.Equal(50, vm.VisibleRows.Count);
        Assert.Contains("of 50", vm.PageLabel);
        vm.SearchText = "zzz-no-match";
        Assert.Empty(vm.VisibleRows);
        Assert.Contains("No rows match", vm.PageLabel);
    }

    [Fact]
    public void Storage_Paging_TurnsPages_WithStableTotals()
    {
        string bulk = Path.Combine(Path.GetTempPath(), "p22page" + Guid.NewGuid().ToString("N"));
        long nowTicks = DateTime.UtcNow.Ticks;
        using (var db = OpenScanDb())
        {
            for (int i = 0; i < 150; i++)
            {
                db.UpsertFingerprint(
                    Path.Combine(bulk, $"file{i:D3}.tmp"), 100 + i, nowTicks, null, 1);
            }
        }

        var vm = new CleanerViewModel(OpenScanDb, () => []);
        vm.Refresh();

        string firstPageHead = vm.VisibleRows[0].Detail.FullPath;
        vm.NextPage();
        Assert.Equal(50, vm.VisibleRows.Count);
        Assert.True(vm.HasPrevPage);
        Assert.False(vm.HasNextPage);
        Assert.Contains("101–150 of 150", vm.PageLabel);
        Assert.DoesNotContain(vm.VisibleRows, r => r.Detail.FullPath == firstPageHead);
        vm.PrevPage();
        Assert.Equal(100, vm.VisibleRows.Count);
        Assert.Equal(firstPageHead, vm.VisibleRows[0].Detail.FullPath);
        // Selection survives page turns (the set is the memory).
        vm.VisibleRows[0].IsSelected = true;
        Assert.Contains("1 items", vm.CheckedLine);
        vm.NextPage();
        Assert.Contains("1 items", vm.CheckedLine);
        vm.PrevPage();
        Assert.True(vm.VisibleRows[0].IsSelected);
    }

    [Fact]
    public void Storage_GroupChips_PageSets_Dirs_Apps()
    {
        using (var db = OpenScanDb())
        {
            db.UpsertFingerprint(@"X:\P22\setqx7\a.zip", 1000, 1, "DUP", 1);
            db.UpsertFingerprint(@"X:\P22\setqx7\b.zip", 1000, 2, "DUP", 1);
            db.UpsertFingerprint(@"X:\P22\onlyqx9\c.zip", 500, 3, "SOLO", 1);
        }

        var vm = new CleanerViewModel(OpenScanDb, () => []);
        vm.Refresh();

        vm.SelectedChip = "Duplicates";
        var dupe = Assert.Single(vm.VisibleRows);
        Assert.Equal(StorageRowKind.Duplicate, dupe.Kind);
        Assert.Contains("1 sets", vm.PageLabel);
        Assert.Contains("spare", vm.PageLabel);
        vm.SelectedChip = "Orphans";
        // Real orphan fold over the fixture (1970 mtimes, dir names
        // that match no real uninstall entry): both dirs leftover.
        Assert.Equal(2, vm.VisibleRows.Count);
        Assert.All(vm.VisibleRows, r => Assert.Equal(StorageRowKind.Orphan, r.Kind));
        Assert.All(vm.VisibleRows, r => Assert.Contains("NoUninstallEntry", r.Detail.KnowLine));
        vm.SelectedChip = "Apps";
        Assert.Empty(vm.VisibleRows);
        Assert.Contains("0 apps", vm.PageLabel);
    }

    [Fact]
    public void Storage_TreemapScope_SetsFolderScope()
    {
        SeedFingerprints();
        var vm = new CleanerViewModel(OpenScanDb, () => []);
        vm.Refresh();

        Assert.True(vm.SetTreemapScope("Windows"));
        Assert.True(vm.HasFolderScope);
        Assert.Contains("Windows", vm.FolderScopeLabel);
        // Complement bucket has no prefix: no-op, honestly false.
        Assert.False(vm.SetTreemapScope("Other"));
        vm.ClearFolderScope();
        Assert.False(vm.HasFolderScope);
        Assert.Empty(vm.FolderScope);
    }

    [Fact]
    public void Storage_LimitsLine_StatesCaveats()
    {
        var line = CleanerViewModel.BuildLimitsLine(new AttrStats(2, 200, 1, 100, 4));
        Assert.Contains("2 sparse files", line);
        Assert.Contains("1 cloud placeholder", line);
        Assert.Contains("3 files", line);
        Assert.Contains("link path", line);
        var clean = CleanerViewModel.BuildLimitsLine(new AttrStats(0, 0, 0, 0, 0));
        Assert.Contains("link path", clean);
    }

    [Fact]
    public void Storage_TreemapFromBuckets_PartitionsTotal()
    {
        using var db = OpenScanDb();
        db.UpsertFingerprint(@"C:\W\a.dll", 100, 1, null, 1);
        db.UpsertFingerprint(@"C:\W\b.dll", 50, 1, null, 1);
        db.UpsertFingerprint(@"C:\P\app\c.exe", 1000, 1, null, 1);
        db.UpsertFingerprint(@"C:\WindowsOld\squat\d.dll", 10, 1, null, 1);
        db.UpsertFingerprint(@"D:\data\x.bin", 5, 1, null, 1);
        var cats = CleanerViewModel.BuildTreemapFromBuckets(
            db, @"C:\W", @"C:\P", @"C:\P86", @"C:\U");
        Assert.Equal(db.SumFingerprintBytes(), cats.Sum(c => c.Bytes));
        var other = Assert.Single(cats, c => c.Key == "Other");
        // Prefix boundary: C:\WindowsOld is not C:\W.
        Assert.Equal(15, other.Bytes);
        var apps = Assert.Single(cats, c => c.Key == "Applications");
        Assert.Equal(1000, apps.Bytes);
        Assert.Single(apps.TopFiles);
        Assert.Equal(0, apps.RestBytes);
    }

    [Fact]
    public void Storage_Never_Row_Refuses_Selection()
    {
        var row = FileRow("c.sys", "NEVER", 300);
        Assert.False(row.IsSelectable);
        row.IsSelected = true;
        Assert.False(row.IsSelected);
        var ok = FileRow("a.tmp", "REVIEW", 100);
        Assert.True(ok.IsSelectable);
        ok.IsSelected = true;
        Assert.True(ok.IsSelected);
    }

    private static StorageRow FileRow(string name, string tier, long size)
    {
        return new StorageRow(
            StorageRowKind.File, name, @"C:\T", size + " B", size,
            tier, tier, tier != "NEVER",
            new StorageDetail(
                @"C:\T\" + name, size + " B", "Unknown", "Not requested",
                tier, "reasons", "verify", "evidence", [], null));
    }

    [Fact]
    public void Drivers_Collects_WithWellformedRows()
    {
        var vm = new DriversViewModel();
        vm.Refresh();

        Assert.False(string.IsNullOrWhiteSpace(vm.Summary));
        Assert.All(vm.Problems, r =>
        {
            Assert.False(string.IsNullOrWhiteSpace(r.Device));
            Assert.StartsWith("Code ", r.Code);
        });
        Assert.All(vm.Drivers, r => Assert.False(string.IsNullOrWhiteSpace(r.Device)));
    }

    [Fact]
    public void Drivers_PhantomToggle_FiltersCode45Only()
    {
        var vm = new DriversViewModel();
        vm.Apply(new DriversViewModel.DriversSnapshot(
            "s", "c",
            [
                new DriverProblemRow("Ghost", "Not connected", "Code 45", true, "ID-GHOST"),
                new DriverProblemRow("Real", "Failed", "Code 10", false, "ID-REAL"),
            ],
            [], [], DateTime.UtcNow));

        Assert.Equal(2, vm.Problems.Count);
        vm.ShowDisconnected = false;
        Assert.Single(vm.Problems);
        Assert.Equal("Real", vm.Problems[0].Device);
        vm.ShowDisconnected = true;
        Assert.Equal(2, vm.Problems.Count);
    }

    [Fact]
    public void Drivers_BuildDevices_Merges_Problems_First()
    {
        var problems = new List<DriverProblemRow>
        {
            new("USB device", "Cannot start", "Code 10", false, "USB\\VID_1"),
            new("Ghost CD", "Not connected", "Code 45", true, "ID-GHOST"),
        };
        var drivers = new List<DriverRow>
        {
            new("USB device", "1.0", "Vendor", "Error"),
            new("Ethernet", "2.0", "Intel", "OK"),
        };
        var rows = DriversViewModel.BuildDevices(problems, drivers, "Today, 10:00").ToList();
        Assert.Equal(3, rows.Count);
        Assert.Equal("Problem", rows[0].StatusKind);
        Assert.Equal("Code 10", rows[0].Status);
        Assert.Equal("1.0", rows[0].Version);
        Assert.Equal("USB\\VID_1", rows[0].Detail.InstanceId);
        Assert.Equal("Phantom", rows[1].StatusKind);
        Assert.Equal("Working", rows[2].StatusKind);
        Assert.Equal("Ethernet", rows[2].Device);
    }

    [Fact]
    public void Drivers_BuildDevices_MissingStatusIsWorking_OnlyFaultIsProblem()
    {
        // Win32_PnPSignedDriver.Status is routinely empty; the VM once showed
        // every device under "Problems" because only "OK" counted as working.
        var drivers = new List<DriverRow>
        {
            new("Empty", "1.0", "Vendor", ""),
            new("Dash", "1.0", "Vendor", "—"),
            new("Bad", "1.0", "Vendor", "Error"),
            new("Stopping", "1.0", "Vendor", "Stopped"),
        };
        var rows = DriversViewModel.BuildDevices([], drivers, "Today, 10:00").ToList();

        Assert.Equal("Working", rows[0].StatusKind);
        Assert.Equal("Working", rows[1].StatusKind);
        Assert.Equal("Problem", rows[2].StatusKind);
        Assert.Equal("Error", rows[2].Status);
        Assert.Equal("Working", rows[3].StatusKind);
    }

    [Fact]
    public void Drivers_BuildTopologyDisk_Flags_Unmounted()
    {
        var disk = new DiskTopologyRecord(
            1, "USB disk", "USB", "Healthy", "MBR", 1024L, false,
            [
                new PartitionRecord(1, 512L, "D", "Basic", false, false,
                    new VolumeRecord("D", "NTFS", "Data", 512L, 100L, "Healthy", "path")),
                new PartitionRecord(2, 16L, null, "Unknown", false, false, null),
            ]);
        var card = DriversViewModel.BuildTopologyDisk(disk);
        Assert.Equal("Disk 1", card.Name);
        Assert.Equal(2, card.Partitions.Count);
        Assert.True(card.HasIssue);
        Assert.Contains("not mounted", card.StatusLine);
    }

    [Fact]
    public void Threats_Collects_WithBanner_AndBoundedTables()
    {
        var vm = new ThreatsViewModel();
        vm.Refresh();

        Assert.False(string.IsNullOrWhiteSpace(vm.Banner));
        Assert.True(vm.Processes.Count <= 100);
        Assert.All(vm.Detections, r => Assert.False(string.IsNullOrWhiteSpace(r.Threat)));
    }

    [Fact]
    public void Threats_Apply_Quarantine_Comes_Only_From_Current_List()
    {
        // T52: quarantined-looking detection history NEVER lists
        // anything — only QuarantineItems (the live list) does.
        var vm = new ThreatsViewModel();
        vm.Apply(new ThreatsViewModel.ThreatsSnapshot(
            "b", "d", "On", "Today", "Today", "c",
            [
                new ThreatDetectionRow("T1", "High", @"C:\a", "now", "Quarantined by Defender", false),
                new ThreatDetectionRow("T2", "Low", @"C:\b", "now", "Removed by Defender", false),
            ],
            [], [], 0, 0, 0, "n",
            QuarantineItems:
            [
                new QuarantineRow("Q1", "T1", @"C:\a", "today", "explained"),
            ],
            QuarantineNote: "note"));
        Assert.Single(vm.Quarantine);
        Assert.Equal("Q1", vm.Quarantine[0].Name);
        Assert.Equal("note", vm.QuarantineNote);

        var vm2 = new ThreatsViewModel();
        vm2.Apply(new ThreatsViewModel.ThreatsSnapshot(
            "b", "d", "On", "Today", "Today", "c",
            [
                new ThreatDetectionRow("T1", "High", @"C:\a", "now", "Quarantined by Defender", false),
            ],
            [], [], 0, 0, 0, "n"));
        Assert.Empty(vm2.Quarantine);
    }

    [Fact]
    public void Threats_DetectionEvidence_Maps_Record()
    {
        // A09: evidence attaches only to its requesting selection
        // (current token + matching path); the mapping assertions
        // below are unchanged.
        var vm = new ThreatsViewModel();
        vm.SelectedDetection = new ThreatDetectionRow("T", "High", @"C:\a", "now", "", false);
        vm.SetDetectionEvidence(
            vm.BeginDetectionEvidence(),
            new StaticFileEvidenceRecord(@"C:\a", true, 10, "ABC", true, "Subj", "Iss", null),
            @"C:\a");
        Assert.Equal("ABC", vm.DetectionEvidence!.HashDisplay);
        Assert.Contains("Signed", vm.DetectionEvidence.SignedLine);
        Assert.Equal("Present on disk", vm.DetectionEvidence.AvailabilityLine);

        vm.SelectedDetection = new ThreatDetectionRow("T", "High", @"C:\b", "now", "", false);
        vm.SetDetectionEvidence(
            vm.BeginDetectionEvidence(),
            new StaticFileEvidenceRecord(@"C:\b", false, null, null, false, null, null, null),
            @"C:\b");
        Assert.Contains("Not present", vm.DetectionEvidence!.AvailabilityLine);

        vm.SelectedDetection = new ThreatDetectionRow("T", "High", @"C:\c", "now", "", false);
        vm.SetDetectionEvidence(vm.BeginDetectionEvidence(), null, @"C:\c");
        Assert.Equal("Not computed", vm.DetectionEvidence!.HashDisplay);
    }

    [Fact]
    public void Threats_FileCheck_Maps_Record()
    {
        // A09: only the newest file-check request attaches; the
        // mapping assertions below are unchanged.
        var vm = new ThreatsViewModel();
        vm.SetFileCheck(
            vm.BeginFileCheck(),
            new StaticFileEvidenceRecord(@"C:\a.txt", true, 5, null, false, null, null, null),
            @"C:\a.txt", null);
        Assert.Equal("a.txt", vm.FileCheck!.Title);
        Assert.Contains("Unsigned", vm.FileCheck.SignedLine);

        vm.SetFileCheck(vm.BeginFileCheck(), null, @"C:\missing", "denied");
        Assert.Equal("denied", vm.FileCheck!.SizeLine);
    }

    [Fact]
    public void Crashes_Collects_AndDetailsFirstRow()
    {
        var vm = new CrashesViewModel();
        vm.Refresh();

        Assert.False(string.IsNullOrWhiteSpace(vm.Summary));
        if (vm.Timeline.Count > 0)
        {
            Assert.Equal(0, vm.SelectedIndex);
            Assert.False(string.IsNullOrWhiteSpace(vm.DetailBody));
        }
    }

    [Fact]
    public void History_ShowsSeededRuns_AndExportsParse()
    {
        using (var db = OpenScanDb())
        {
            long id = db.BeginRun(@"C:\Seed", 1, "Turbo");
            db.EndRun(id, 10, 1000, 5, 1200);
        }

        using (var agent = OpenAgentDb())
        {
            agent.UpsertInvestigation("inv-1", "seed", "seed goal", "Done", null, 1, 1, 2, 100, 0.0, 0, 0, 0, 0, 0, false, 0.001, "[]");
            agent.UpsertFinding("f-1", "inv-1", 1, "Committed", "seed observation", "interp", "[]", "", "");
        }

        var vm = new HistoryViewModel(OpenScanDb, OpenAgentDb);
        vm.Refresh();

        Assert.Single(vm.Runs);
        Assert.Single(vm.Investigations);
        Assert.Single(vm.Findings);
        Assert.Contains("Vault is empty", vm.VaultState);

        using var json = JsonDocument.Parse(vm.BuildAuditJson());
        Assert.True(json.RootElement.TryGetProperty("runs", out _));
        Assert.True(json.RootElement.TryGetProperty("vault", out _));
        Assert.Contains("<html>", vm.BuildAuditHtml());
        Assert.Contains("seed observation", vm.BuildAuditHtml());
    }

    // P2-01: unknown cost renders as "Cost estimate unavailable",
    // never $0.00 (which would claim a free investigation).
    [Fact]
    public void History_UnknownCost_Shows_Unavailable_Not_Zero()
    {
        using (var agent = OpenAgentDb())
        {
            agent.UpsertInvestigation(
                "inv-nocost", "seed", "seed goal", "Done", null, 1, 1,
                2, 100, 5.0, 10, 5, 0, 0, 500, true, null, "[]");
        }

        var vm = new HistoryViewModel(OpenScanDb, OpenAgentDb);
        vm.Refresh();

        var row = Assert.Single(vm.Investigations);
        Assert.Equal("Cost estimate unavailable", row.Cost);
    }

    [Fact]
    public void Reports_Generate_BuildsParseableReport()
    {
        SeedFingerprints();
        var vm = new ReportsViewModel(OpenScanDb);

        vm.Generate();

        Assert.Contains("technician report", vm.Preview);
        Assert.False(string.IsNullOrWhiteSpace(vm.NotInReport));
        using var json = JsonDocument.Parse(vm.BuildReportJson());
        Assert.True(json.RootElement.TryGetProperty("OpenIssues", out _));
        Assert.Contains("<html>", vm.BuildReportHtml());
        Assert.Contains("Not in this report", vm.BuildReportHtml());
    }

    [Fact]
    public void Reports_RepeatedWarnings_GroupsSameDevice()
    {
        var records = new[]
        {
            new TargetedEventRecord("System", 1, 153, "Warning", DateTime.UtcNow, "disk", "IO failed for Disk 0", []),
            new TargetedEventRecord("System", 2, 153, "Warning", DateTime.UtcNow, "disk", "IO failed for Disk 0", []),
            new TargetedEventRecord("System", 3, 55, "Error", DateTime.UtcNow, "ntfs", "Corrupt on Disk 0", []),
            new TargetedEventRecord("System", 4, 1001, "Error", DateTime.UtcNow, "BugCheck", "crash", []),
        };

        Assert.Equal("3 (same device: DISK 0)", ReportsViewModel.GroupRepeatedWarnings(records));
        Assert.Equal("None", ReportsViewModel.GroupRepeatedWarnings([]));
    }

    [Fact]
    public void Reports_Generate_ScopeHonest_WithAndWithoutRuns()
    {
        var empty = new ReportsViewModel(OpenScanDb);
        empty.Generate();
        Assert.Contains("No scan on record", empty.Draft!.ScanScope);
        Assert.Contains("No scan on record", empty.Draft.CoverageLine);
        Assert.Contains("This PC", empty.DraftTitle);
        Assert.Equal("Not yet exported", empty.DraftState);

        using (var db = OpenScanDb())
        {
            long id = db.BeginRun(@"C:\Seed", 3, "Balanced");
            db.EndRun(id, 50, 500, 0, 60_000, "Completed", null, 1);
        }

        var seeded = new ReportsViewModel(OpenScanDb);
        seeded.Generate();
        Assert.Contains(@"C:\Seed", seeded.Draft!.ScanScope);
        Assert.Contains("Balanced", seeded.Draft.ScanScope);
        Assert.Contains("uninspected", seeded.Draft.CoverageLine);
    }

    [Fact]
    public void Reports_WriteExport_RoundTripsBothFormats()
    {
        var vm = new ReportsViewModel(OpenScanDb);
        vm.Generate();

        string jsonPath = Path.Combine(_dir, "report.json");
        vm.ExportFormat = "JSON";
        Assert.True(vm.WriteExport(jsonPath));
        using var json = JsonDocument.Parse(File.ReadAllText(jsonPath));
        Assert.True(json.RootElement.TryGetProperty("OpenIssues", out _));
        Assert.Contains("Exported JSON", vm.DraftState);

        string htmlPath = Path.Combine(_dir, "report.html");
        vm.ExportFormat = "HTML";
        Assert.True(vm.WriteExport(htmlPath));
        Assert.Contains("<html>", File.ReadAllText(htmlPath));
    }

    [Fact]
    public void Settings_RoundTrips_AndSanitizes()
    {
        var store = new SettingsStore(_settingsPath);
        var vm = new SettingsViewModel(store, OpenScanDb, OpenAgentDb, () => _dir);

        vm.BalancedCapPercent = 99;
        vm.Theme = "Light";
        vm.FontPercent = 200;

        Assert.Equal(30, vm.BalancedCapPercent);
        Assert.Equal("Light", vm.Theme);
        Assert.Equal(125, vm.FontPercent);

        var reloaded = new SettingsStore(_settingsPath).Load();
        Assert.Equal(30, reloaded.BalancedCapPercent);
        Assert.Equal("Light", reloaded.Theme);
    }

    [Fact]
    public void Settings_CorruptFile_FallsBackToDefaults()
    {
        File.WriteAllText(_settingsPath, "{not json");
        var vm = new SettingsViewModel(new SettingsStore(_settingsPath), OpenScanDb, OpenAgentDb, () => _dir);

        Assert.Equal("Balanced", vm.DefaultScanMode);
        Assert.True(vm.AiEnabled);
    }

    [Fact]
    public void Settings_PauseOnLowBattery_Defaults_True_When_Key_Missing()
    {
        // Pre-A10 settings files lack the key: the record's default
        // parameter value must keep them on the protected default
        // instead of silently flipping to false.
        File.WriteAllText(_settingsPath,
            """{"DefaultScanMode":"Eco","BalancedCapPercent":20,"AiEnabled":true,"NeverTouch":[],"Theme":"Dark","FontScale":1.0}""");
        var loaded = new SettingsStore(_settingsPath).Load();

        Assert.True(loaded.PauseOnLowBattery);
    }

    [Fact]
    public void Settings_PauseOnLowBattery_RoundTrips()
    {
        var vm = new SettingsViewModel(new SettingsStore(_settingsPath), OpenScanDb, OpenAgentDb, () => _dir);
        Assert.True(vm.PauseOnLowBattery);

        vm.PauseOnLowBattery = false;
        Assert.False(new SettingsStore(_settingsPath).Load().PauseOnLowBattery);

        vm.PauseOnLowBattery = true;
        Assert.True(new SettingsStore(_settingsPath).Load().PauseOnLowBattery);
    }

    [Fact]
    public void Settings_PriorityWatch_Defaults_True_When_Key_Missing()
    {
        // Pre-P21 settings files lack the key: the record's default
        // parameter value keeps them on the default-ON watch instead
        // of silently flipping to false.
        File.WriteAllText(_settingsPath,
            """{"DefaultScanMode":"Eco","BalancedCapPercent":20,"AiEnabled":true,"NeverTouch":[],"Theme":"Dark","FontScale":1.0,"PauseOnLowBattery":true}""");
        var loaded = new SettingsStore(_settingsPath).Load();

        Assert.True(loaded.PriorityWatchEnabled);
    }

    [Fact]
    public void Settings_PriorityWatch_RoundTrips_And_Raises_Toggle()
    {
        var vm = new SettingsViewModel(new SettingsStore(_settingsPath), OpenScanDb, OpenAgentDb, () => _dir);
        Assert.True(vm.PriorityWatchEnabled);
        int toggles = 0;
        vm.WatchToggled += (_, _) => toggles++;

        vm.PriorityWatchEnabled = false;
        Assert.False(new SettingsStore(_settingsPath).Load().PriorityWatchEnabled);
        Assert.Equal(1, toggles);

        vm.PriorityWatchEnabled = true;
        Assert.True(new SettingsStore(_settingsPath).Load().PriorityWatchEnabled);
        Assert.Equal(2, toggles);
    }

    [Fact]
    public void Settings_Appearance_RoundTrips()
    {
        var vm = new SettingsViewModel(new SettingsStore(_settingsPath), OpenScanDb, OpenAgentDb, () => _dir);
        Assert.Equal(["Dark", "Light", "System"], vm.Themes);
        Assert.False(vm.ReduceMotion);
        Assert.False(vm.HighContrast);

        int changed = 0;
        vm.AppearanceChanged += (_, _) => changed++;

        vm.Theme = "System";
        vm.ReduceMotion = true;
        vm.HighContrast = true;

        var reloaded = new SettingsStore(_settingsPath).Load();
        Assert.Equal("System", reloaded.Theme);
        Assert.True(reloaded.ReduceMotion);
        Assert.True(reloaded.HighContrast);
        Assert.Equal(2, changed); // Theme + HighContrast; ReduceMotion has no visual to re-apply.

        var vm2 = new SettingsViewModel(new SettingsStore(_settingsPath), OpenScanDb, OpenAgentDb, () => _dir);
        Assert.Equal("System", vm2.Theme);
        Assert.True(vm2.ReduceMotion);
        Assert.True(vm2.HighContrast);
    }

    [Fact]
    public void Settings_Appearance_Legacy_Missing_Keys_Default_Off()
    {
        File.WriteAllText(_settingsPath,
            """{"DefaultScanMode":"Eco","BalancedCapPercent":20,"AiEnabled":true,"NeverTouch":[],"Theme":"Dark","FontScale":1.0,"PauseOnLowBattery":true,"PriorityWatchEnabled":true}""");
        var loaded = new SettingsStore(_settingsPath).Load();

        Assert.False(loaded.ReduceMotion);
        Assert.False(loaded.HighContrast);
    }

    [Fact]
    public void Settings_Theme_System_Kept_Junk_Falls_Back_To_Dark()
    {
        var store = new SettingsStore(_settingsPath);
        var vm = new SettingsViewModel(store, OpenScanDb, OpenAgentDb, () => _dir);
        vm.Theme = "System";
        Assert.Equal("System", new SettingsStore(_settingsPath).Load().Theme);

        File.WriteAllText(_settingsPath,
            """{"DefaultScanMode":"Eco","BalancedCapPercent":20,"AiEnabled":true,"NeverTouch":[],"Theme":"Neon","FontScale":1.0}""");
        Assert.Equal("Dark", new SettingsStore(_settingsPath).Load().Theme);
    }

    [Fact]
    public void ThemeResolver_Maps_System_And_HighContrast()
    {
        Assert.Equal("Dark", ThemeResolver.Resolve("Dark", false, () => 1));
        Assert.Equal("Light", ThemeResolver.Resolve("Light", false, () => 0));
        Assert.Equal("Dark", ThemeResolver.Resolve("System", false, () => 0));
        Assert.Equal("Light", ThemeResolver.Resolve("System", false, () => 1));
        Assert.Equal("Light", ThemeResolver.Resolve("System", false, () => null));
        Assert.Equal("Light", ThemeResolver.Resolve("System", false, () => throw new InvalidOperationException()));
        Assert.Equal("Dark", ThemeResolver.Resolve("Neon", false, () => 1));
        Assert.Equal("HighContrast", ThemeResolver.Resolve("Dark", true, () => 1));
        Assert.Equal("HighContrast", ThemeResolver.Resolve("System", true, () => 1));
    }

    [Fact]
    public void Settings_CloudKey_SaveRemove_RoundTrips_OnTestTarget()
    {
        var target = "Sentinel/Test-" + Guid.NewGuid().ToString("N");
        var vm = new SettingsViewModel(
            new SettingsStore(_settingsPath), OpenScanDb, OpenAgentDb, () => _dir,
            () => new CloudKeyStore(target));
        try
        {
            Assert.Contains("not saved", vm.CloudKeyLine);
            vm.SaveCloudKey("  ");
            Assert.Contains("does not look like a key", vm.KeyError);

            vm.SaveCloudKey("LLM_TEST_SETTINGS_ROUNDTRIP");
            Assert.Equal(string.Empty, vm.KeyError);
            Assert.Contains("saved", vm.CloudKeyLine);
            Assert.DoesNotContain("LLM_TEST", vm.CloudKeyLine);
        }
        finally
        {
            vm.RemoveCloudKey();
        }

        Assert.Contains("not saved", vm.CloudKeyLine);
    }

    [Fact]
    public void Settings_NeverList_Validates_AndPersists()
    {
        var vm = new SettingsViewModel(new SettingsStore(_settingsPath), OpenScanDb, OpenAgentDb, () => _dir);

        vm.NewNeverPath = Path.Combine(_dir, "missing");
        vm.AddNeverCommand.Execute(null);
        Assert.Contains("does not exist", vm.NeverError);
        Assert.Empty(vm.NeverTouch);

        vm.NewNeverPath = _dir;
        vm.AddNeverCommand.Execute(null);
        Assert.Single(vm.NeverTouch);
        Assert.Contains(_dir, new SettingsStore(_settingsPath).Load().NeverTouch);

        vm.RemoveNeverCommand.Execute(_dir);
        Assert.Empty(vm.NeverTouch);
    }

    [Fact]
    public void Settings_ClearCache_EmptiesFingerprints_KeepsRuns()
    {
        SeedFingerprints();
        using (var db = OpenScanDb())
        {
            long id = db.BeginRun(@"C:\Seed", 1, "Eco");
            db.EndRun(id, 3, 300, 0, 10);
        }

        var vm = new SettingsViewModel(new SettingsStore(_settingsPath), OpenScanDb, OpenAgentDb, () => _dir);
        vm.DeleteDataCommand.Execute(null);

        using var check = OpenScanDb();
        Assert.Equal(0, check.CountFingerprints());
        Assert.Single(check.ListRuns());
        Assert.Contains("re-discovers", vm.ActionNote);
    }

    [Fact]
    public void Settings_PayloadPreview_EmptyUntilProvided()
    {
        var vm = new SettingsViewModel(new SettingsStore(_settingsPath), OpenScanDb, OpenAgentDb, () => _dir);
        vm.ShowPayloadsCommand.Execute(null);
        Assert.Contains("No AI payloads", vm.PayloadPreview);

        vm.PayloadProvider = () => ["[model-request] {\"a\":1}"];
        vm.ShowPayloadsCommand.Execute(null);
        Assert.Contains("model-request", vm.PayloadPreview);
    }

    [Fact]
    public void MainViewModel_ListsNinePages_AndHealthyDb()
    {
        // A08: the startup probe reads the override path, so pass
        // the temp store (never the production database).
        using var _ = OpenScanDb();
        var main = new MainViewModel(OpenScanDb, new ImmediateDispatcher(), _dbPath);

        Assert.Equal(9, main.PageNames.Count);
        Assert.Equal(9, main.PageNames.Distinct().Count());
        Assert.Null(main.DbError);
        Assert.False(string.IsNullOrWhiteSpace(main.AdminBanner));
    }

    [Fact]
    public void MainViewModel_CorruptDb_SurfacesError()
    {
        using var _ = OpenScanDb();
        var main = new MainViewModel(OpenScanDb, new ImmediateDispatcher(), _dbPath);
        Assert.Null(main.DbError);

        // A08: real garbage bytes (not a throwing factory) prove
        // the read-only startup probe detects corruption without
        // mutating the store. (RebuildDataCommand is covered by
        // StoreRecoveryTests via the same override.)
        string brokenPath = Path.Combine(_dir, "broken.db");
        File.WriteAllBytes(brokenPath, [0xDE, 0xAD, 0xBE, 0xEF]);
        var broken = new MainViewModel(OpenScanDb, new ImmediateDispatcher(), brokenPath);
        Assert.Contains("corrupt", broken.DbError);
        Assert.Equal(
            [0xDE, 0xAD, 0xBE, 0xEF],
            File.ReadAllBytes(brokenPath));
    }

    [Theory]
    [InlineData(1001, "Crash")]
    [InlineData(41, "Crash")]
    [InlineData(6008, "Crash")]
    [InlineData(1000, "Crash")]
    [InlineData(1002, "Hang")]
    [InlineData(55, "Disk warning")]
    [InlineData(153, "Disk warning")]
    [InlineData(19, "Update")]
    public void Crashes_TypeFor_MapsKnownIds(int eventId, string expected)
    {
        var anchor = new TargetedEventRecord("System", 1, eventId, "Error", DateTime.UtcNow, "Test", "m", []);
        Assert.Equal(expected, CrashesViewModel.TypeFor(anchor));
    }

    [Fact]
    public void Crashes_BucketizeWeeks_StacksByType()
    {
        var now = DateTime.UtcNow;
        var rows = new[]
        {
            MakeCrashRow(now.AddDays(-1), 1001, 0),
            MakeCrashRow(now.AddDays(-2), 1002, 1),
            MakeCrashRow(now.AddDays(-9), 153, 2),
            MakeCrashRow(now.AddDays(-40), 1001, 3),
        };

        var weeks = CrashesViewModel.BucketizeWeeks(rows, now);

        Assert.Equal(5, weeks.Count);
        Assert.Equal(2, weeks[4].Total);
        Assert.Equal(1, weeks[4].Crash);
        Assert.Equal(1, weeks[4].Hang);
        Assert.Equal(1, weeks[3].Disk);
        Assert.DoesNotContain(weeks.Take(3), w => w.Total > 0);
    }

    [Fact]
    public void Crashes_Filters_RangeTypeAndRelated()
    {
        var now = DateTime.UtcNow;
        var anchors = new[]
        {
            new TargetedEventRecord("System", 1, 1001, "Error", now.AddDays(-1), "BugCheck", "crash", []),
            new TargetedEventRecord("System", 2, 1002, "Error", now.AddDays(-2), "Hang", "hang", []),
            new TargetedEventRecord("System", 3, 1001, "Error", now.AddDays(-20), "BugCheck", "old", []),
        };
        var cards = anchors.Select(a => new CrashCard(
            "t", "w",
            [new CrashFinding("cause", KnowledgePack.Confidence.Medium, [])],
            [], "trend", [], [])).ToList();
        var rows = anchors.Select((a, i) => new CrashesViewModel.CrashRow(
            "when", CrashesViewModel.TypeFor(a), "s", a.Id, i, a)).ToList();
        var vm = new CrashesViewModel();
        vm.Apply(new CrashesViewModel.CrashesSnapshot("s", "c", rows, cards));

        Assert.Equal(3, vm.VisibleRows.Count);

        vm.SelectedRange = "Last 7 days";
        Assert.Equal(2, vm.VisibleRows.Count);
        Assert.Equal(1, vm.CrashCount);

        vm.SelectedEventType = "Hang";
        Assert.Single(vm.VisibleRows);

        vm.SelectedEventType = "All event types";
        vm.RelatedEventId = 1001;
        Assert.True(vm.HasRelatedFilter);
        Assert.Single(vm.VisibleRows);

        Assert.NotNull(vm.SelectedRow);
        Assert.Contains("cause", vm.DetailBody);
        Assert.Contains("Not named", vm.SelectedDevice);
    }

    [Theory]
    [InlineData("Completed", "Scan completed", "Good")]
    [InlineData("Cancelled", "Scan cancelled", "Bad")]
    [InlineData("Failed", "Scan failed", "Bad")]
    public void History_ScanTitles_MapStatus(string status, string title, string kind)
    {
        Assert.Equal(title, HistoryViewModel.ScanTitle(status));
        Assert.Equal(kind, HistoryViewModel.StatusKindFor(status));
    }

    [Theory]
    [InlineData(38_000, "38s")]
    [InlineData(134_000, "2m 14s")]
    [InlineData(3_720_000, "1h 02m")]
    public void History_FormatElapsed_RendersClock(long ms, string expected)
    {
        Assert.Equal(expected, HistoryViewModel.FormatElapsed(ms));
    }

    [Fact]
    public void History_GroupEvents_BucketsByAge()
    {
        // Anchored to local noon dates: no dependence on the wall clock,
        // so a run near midnight cannot merge buckets (regression: the
        // -1h event fell on "yesterday" after 00:00 local).
        var localNoon = DateTime.Today.AddHours(12);
        var now = localNoon.AddHours(6).ToUniversalTime();
        var events = new[]
        {
            MakeHistoryEvent(localNoon.AddHours(-3).ToUniversalTime()),
            MakeHistoryEvent(localNoon.AddDays(-3).ToUniversalTime()),
            MakeHistoryEvent(localNoon.AddDays(-10).ToUniversalTime()),
        };

        var groups = HistoryViewModel.GroupEvents(events, now);

        Assert.Equal(3, groups.Count);
        Assert.Equal("Today", groups[0].Label);
        Assert.Equal("Earlier this week", groups[1].Label);
        Assert.Equal("Earlier", groups[2].Label);
    }

    [Fact]
    public void History_Collects_Filters_AndExports()
    {
        using (var db = OpenScanDb())
        {
            long id = db.BeginRun(@"C:\Seed", 7, "Balanced");
            db.EndRun(id, 100, 1000, 0, 134_000, "Completed", null, 2);
            db.RecordAbortedRun(@"C:\Seed", 8, 10, 100, 0, 38_000, "Cancelled", null, "Balanced");
        }

        using (var agent = OpenAgentDb())
        {
            agent.UpsertInvestigation(
                "h1", "seed", "Check growth", "Completed", null, 1, 7,
                3, 2048, 12.5, 0, 0, 0, 0, 0, false, null, "[]");
            agent.UpsertFinding("f1", "h1", 1, "Committed", "obs", "interp", "[]", "limits", "next");
        }

        var vm = new HistoryViewModel(OpenScanDb, OpenAgentDb);
        vm.Refresh();

        Assert.Equal(2, vm.Runs.Count);
        Assert.Single(vm.Investigations);
        Assert.NotEmpty(vm.Groups);
        Assert.NotNull(vm.SelectedEvent);
        Assert.NotEmpty(vm.DrawerFields);

        vm.SelectedKind = "Scans";
        Assert.DoesNotContain(vm.Groups.SelectMany(g => g.Events), e => e.Kind == "Investigation");

        vm.SelectedKind = "Findings";
        Assert.Contains(vm.Groups.SelectMany(g => g.Events), e => e.Kind == "Investigation");

        vm.SelectedKind = "Actions";
        Assert.Empty(vm.Groups);
        Assert.Contains("don't change", vm.EmptyText);

        string json = vm.BuildAuditJson();
        Assert.Contains("C:\\\\Seed", json);
        Assert.Contains("Check growth", json);
        string html = vm.BuildAuditHtml();
        Assert.Contains("sentinel history", html.ToLowerInvariant());

        string path = Path.Combine(_dir, "history.json");
        Assert.True(vm.WriteExport(path, "json"));
        Assert.Contains("C:\\\\Seed", File.ReadAllText(path));
    }

    // R14.1/R26.2: the drawer tells all four truths — evidence,
    // wire bytes, provider tokens, cost — with "unavailable",
    // never invented zeros, when the provider stayed silent.
    [Fact]
    public void History_Drawer_Shows_Four_Truths_With_Honest_Unknowns()
    {
        using (var agent = OpenAgentDb())
        {
            agent.UpsertInvestigation(
                "w1", "seed", "Metered run", "Completed", null, 1, 7,
                4, 2048, 12.5, 1200, 300, 50, 100, 99000, true, 0.0042, "[]");
            agent.UpsertInvestigation(
                "w2", "seed", "Offline run", "Completed", null, 1, 7,
                0, 512, 3.0, 0, 0, 0, 0, 0, false, null, "[]");
        }

        var vm = new HistoryViewModel(OpenScanDb, OpenAgentDb);
        vm.Refresh();

        var metered = vm.Groups.SelectMany(g => g.Events)
            .First(e => e.Kind == "Investigation" && e.Investigation?.Goal == "Metered run");
        vm.SelectedEvent = metered;
        var fields = vm.DrawerFields.ToDictionary(f => f.Label);
        Assert.Equal("96.7 KB", fields["Sent on the wire"].Value);
        Assert.Contains("1,200 in", fields["Provider tokens"].Value);
        Assert.Contains("300 out", fields["Provider tokens"].Value);
        Assert.Contains("50 reasoning", fields["Provider tokens"].Value);
        Assert.Contains("100 cached", fields["Provider tokens"].Value);
        Assert.Equal("$0.0042", fields["Estimated cost"].Value);

        var offline = vm.Groups.SelectMany(g => g.Events)
            .First(e => e.Kind == "Investigation" && e.Investigation?.Goal == "Offline run");
        vm.SelectedEvent = offline;
        var offFields = vm.DrawerFields.ToDictionary(f => f.Label);
        Assert.Equal("Token counts unavailable", offFields["Provider tokens"].Value);
        Assert.Equal("Cost estimate unavailable", offFields["Estimated cost"].Value);
        Assert.Equal("0 B", offFields["Sent on the wire"].Value);
    }

    [Fact]
    public void History_Labels_Cost()
    {
        Assert.Equal("Cost estimate unavailable", HistoryViewModel.CostLabel(null));
        Assert.Equal("$1.2346", HistoryViewModel.CostLabel(1.23456));
    }

    private static HistoryViewModel.HistoryEvent MakeHistoryEvent(DateTime time) =>
        new("Scan", "Scan completed", "Local collector", "d", time, "l1", "l2", "Good",
            null, null, [], null, null);

    private static CrashesViewModel.CrashRow MakeCrashRow(DateTime time, int eventId, int index)
    {
        var anchor = new TargetedEventRecord("System", 1, eventId, "Error", time, "Test", "m", []);
        return new CrashesViewModel.CrashRow("w", CrashesViewModel.TypeFor(anchor), "s", eventId, index, anchor);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        try
        {
            Directory.Delete(_dir, true);
        }
        catch
        {
            // Best effort.
        }
    }
}
