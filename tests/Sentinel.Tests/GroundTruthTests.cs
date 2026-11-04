using Sentinel.App.ViewModels;
using Sentinel.Engine.CrashDoctor;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.Tests;

// P24: device/disk/crash ground truth. Pure-function pins are exact;
// live-collector tests assert shape (sorted, bounded, well-formed),
// never fixed machine data.
public sealed class GroundTruthTests
{
    private const string SampleAnalysis = """
        DRIVER_IRQL_NOT_LESS_OR_EQUAL (d1)
        An attempt was made to access a pageable address at an
        interrupt request level that is too high.
        BugCheck D1, {0, 2, 0, fffff80012345678}

        *** Probably caused by : NETIO.SYS ( NETIO!StreamInject+123 )

        BUGCHECK_CODE:  d1
        BUGCHECK_P1: 0

        MODULE_NAME: NETIO

        IMAGE_NAME:  NETIO.SYS

        STACK_TEXT:
        fffff800`11111111 fffff800`22222222 : 00000000`00000000 frame-one
        fffff800`11111112 fffff800`22222223 : 00000000`00000000 frame-two
        STACK_COMMAND:  .cxr; kb
        SYMBOL_NAME:  NETIO!StreamInject+123
        """;

    [Fact]
    public void AnalyzeParser_ReadsCode_Module_Stack()
    {
        var parsed = MinidumpInspector.ParseAnalyzeOutput(SampleAnalysis);
        Assert.NotNull(parsed);
        Assert.Equal(0xD1u, parsed.Code);
        Assert.Equal("NETIO", parsed.Module);
        Assert.NotNull(parsed.StackHead);
        Assert.Contains("frame-one", parsed.StackHead);
        Assert.Contains("frame-two", parsed.StackHead);
        Assert.DoesNotContain("STACK_COMMAND", parsed.StackHead);
    }

    [Fact]
    public void AnalyzeParser_NamedBugCheck_KeepsName()
    {
        var parsed = MinidumpInspector.ParseAnalyzeOutput(
            "KERNEL_SECURITY_CHECK_FAILURE (139)\nBugCheck 139, {3, ffff}\nMODULE_NAME: nt\n");
        Assert.NotNull(parsed);
        Assert.Equal(0x139u, parsed.Code);
        Assert.Equal("KERNEL_SECURITY_CHECK_FAILURE", parsed.Name);
    }

    [Fact]
    public void AnalyzeParser_Unparseable_ReturnsNull()
    {
        Assert.Null(MinidumpInspector.ParseAnalyzeOutput(string.Empty));
        Assert.Null(MinidumpInspector.ParseAnalyzeOutput("no bugcheck here\nMODULE_NAME: x\n"));
        // A stack without a code is not an analysis.
        Assert.Null(MinidumpInspector.ParseAnalyzeOutput("STACK_TEXT:\nframe\n"));
    }

    [Fact]
    public void AnalyzeParser_CapsStackFrames()
    {
        var frames = string.Join(
            "\n", Enumerable.Range(0, 30).Select(i => $"frame-{i:00} 00000000`00000000"));
        var parsed = MinidumpInspector.ParseAnalyzeOutput(
            $"BugCheck D1, {{0}}\nMODULE_NAME: m\nSTACK_TEXT:\n{frames}\n");
        Assert.NotNull(parsed);
        Assert.NotNull(parsed.StackHead);
        Assert.Contains("frame-09", parsed.StackHead);
        Assert.DoesNotContain("frame-10", parsed.StackHead);
        Assert.True(parsed.StackHead.Length <= MinidumpInspector.StackTextCap);
    }

    [Fact]
    public void FindCdb_ReturnsNull_OrExistingTool()
    {
        string? cdb = MinidumpInspector.FindCdb();
        if (cdb is not null)
        {
            Assert.True(File.Exists(cdb));
            Assert.EndsWith("cdb.exe", cdb, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void DumpListing_NeverThrows_And_NamesFilesOnly()
    {
        var gaps = new List<CollectionGap>();
        var dumps = MinidumpInspector.ListDumps(gaps);
        Assert.All(dumps, d =>
        {
            Assert.False(string.IsNullOrWhiteSpace(d.Name));
            Assert.DoesNotContain(
                Path.DirectorySeparatorChar.ToString(), d.Name, StringComparison.Ordinal);
            Assert.True(
                d.Name.EndsWith(".dmp", StringComparison.OrdinalIgnoreCase)
                || d.Name.Equals("MEMORY.DMP", StringComparison.OrdinalIgnoreCase));
        });
    }

    [Fact]
    public void InspectWith_StandInDir_ListsDumps_AndDegradesWithoutCdb()
    {
        string win = Path.Combine(
            Path.GetTempPath(), "sentinel-p24-" + Guid.NewGuid().ToString("N"));
        string mini = Path.Combine(win, "Minidump");
        Directory.CreateDirectory(mini);
        try
        {
            File.WriteAllBytes(Path.Combine(mini, "012626-12345-01.dmp"), new byte[100]);
            File.WriteAllBytes(Path.Combine(mini, "notes.txt"), new byte[10]);
            File.WriteAllBytes(Path.Combine(win, "MEMORY.DMP"), new byte[50]);

            var result = MinidumpInspector.InspectWith(win, cdb: null, maxDumps: 5);
            Assert.Equal(CollectionStatus.Success, result.Status);
            Assert.Equal(2, result.Records.Count);
            Assert.All(result.Records, r => Assert.Equal("ToolsMissing", r.Status));
            Assert.Contains(result.Records, r => r.Name == "012626-12345-01.dmp");
            Assert.Contains(result.Records, r => r.Name == "MEMORY.DMP");
            Assert.DoesNotContain(result.Records, r => r.Name == "notes.txt");
            Assert.False(result.Truncated);

            var capped = MinidumpInspector.InspectWith(win, cdb: null, maxDumps: 1);
            Assert.Single(capped.Records);
            Assert.True(capped.Truncated);
        }
        finally
        {
            try
            {
                Directory.Delete(win, recursive: true);
            }
            catch
            {
            }
        }
    }

    [Fact]
    public void InspectWith_EmptyDir_ReportsNoDumps()
    {
        string win = Path.Combine(
            Path.GetTempPath(), "sentinel-p24-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(win);
        try
        {
            var result = MinidumpInspector.InspectWith(win, cdb: null);
            Assert.Equal(CollectionStatus.Success, result.Status);
            Assert.Empty(result.Records);
            Assert.Contains("no dumps present", result.Scope);
        }
        finally
        {
            try
            {
                Directory.Delete(win, recursive: true);
            }
            catch
            {
            }
        }
    }

    [Fact]
    public void Inspect_BoundsReports_And_NamesStatuses()
    {
        var result = MinidumpInspector.Inspect(maxDumps: 1);
        Assert.NotEqual(CollectionStatus.Failed, result.Status);
        Assert.True(result.Records.Count <= 1);
        string[] known = ["Analyzed", "ToolsMissing", "AnalyzeFailed"];
        Assert.All(result.Records, r =>
        {
            Assert.Contains(r.Status, known);
            Assert.False(string.IsNullOrWhiteSpace(r.Name));
        });
    }

    [Fact]
    public void Reliability_Records_AreNewestFirst_AndBounded()
    {
        var result = ReliabilityCollector.CollectRecords(
            DateTime.UtcNow.AddDays(-30), maxRows: 50);
        Assert.NotEqual(CollectionStatus.Failed, result.Status);
        Assert.True(result.Records.Count <= 50);
        var times = result.Records.Select(r => r.TimeUtc).ToList();
        Assert.Equal(times.OrderByDescending(t => t), times);
        Assert.All(result.Records, r =>
        {
            Assert.True(r.TimeUtc >= DateTime.UtcNow.AddDays(-31));
            Assert.False(string.IsNullOrWhiteSpace(r.Source));
            Assert.True(r.Message.Length <= 512);
        });
    }

    [Fact]
    public void Reliability_StabilityIndex_IsDailySeries()
    {
        var result = ReliabilityCollector.CollectStabilityIndex(maxRows: 7);
        Assert.NotEqual(CollectionStatus.Failed, result.Status);
        Assert.True(result.Records.Count <= 7);
        var days = result.Records.Select(r => r.DayUtc).ToList();
        Assert.Equal(days.OrderByDescending(t => t), days);
        Assert.All(result.Records, r =>
        {
            if (r.StabilityIndex is double index)
            {
                Assert.InRange(index, 0.0, 10.0);
            }
        });
    }

    [Fact]
    public void TypeFor_WheaClaimsHardwareBucket()
    {
        var whea = new TargetedEventRecord(
            "System", 1, 19, "Warning", DateTime.UtcNow,
            "Microsoft-Windows-WHEA-Logger", "m", []);
        Assert.Equal(CrashesViewModel.TypeHardware, CrashesViewModel.TypeFor(whea));

        var plain = new TargetedEventRecord(
            "System", 2, 19, "Information", DateTime.UtcNow, "Test", "m", []);
        Assert.Equal(CrashesViewModel.TypeUpdate, CrashesViewModel.TypeFor(plain));
    }

    [Fact]
    public void BucketizeWeeks_CountsHardwareSeparately()
    {
        var now = DateTime.UtcNow;
        var whea = new TargetedEventRecord(
            "System", 1, 19, "Warning", now.AddDays(-1),
            "Microsoft-Windows-WHEA-Logger", "m", []);
        var crash = new TargetedEventRecord(
            "System", 2, 1001, "Error", now.AddDays(-1), "BugCheck", "m", []);
        var rows = new[]
        {
            new CrashesViewModel.CrashRow(
                "w", CrashesViewModel.TypeFor(whea), "s", 19, 0, whea),
            new CrashesViewModel.CrashRow(
                "w", CrashesViewModel.TypeFor(crash), "s", 1001, 1, crash),
        };
        var weeks = CrashesViewModel.BucketizeWeeks(rows, now);
        Assert.Equal(1, weeks[4].Hardware);
        Assert.Equal(1, weeks[4].Crash);
        Assert.Equal(2, weeks[4].Total);
    }

    [Fact]
    public void ChkdskLine_StatesAbsence_NeverHealth()
    {
        var empty = CollectionResult<TargetedEventRecord>.Ok(
            [], "Application (Chkdsk + Wininit reports, all levels)");
        Assert.Contains(
            "absence, not health", DriversViewModel.BuildChkdskLine(empty));

        var failed = CollectionResult<TargetedEventRecord>.Fail("scope", "reason");
        Assert.Contains(
            "could not be read", DriversViewModel.BuildChkdskLine(failed));
    }

    [Fact]
    public void ChkdskLine_SummarizesNewestRun_WithRecency()
    {
        var clean = new TargetedEventRecord(
            "Application", 10, 1001, "Information", DateTime.UtcNow.AddDays(-9),
            "Chkdsk", "Windows has scanned the file system and found no problems.", []);
        var line = DriversViewModel.BuildChkdskLine(
            CollectionResult<TargetedEventRecord>.Ok([clean], "scope"));
        Assert.Contains("no problems found", line);
        Assert.Contains("1 report in 90 days", line);
        Assert.Contains("Chkdsk", line);

        var findings = new TargetedEventRecord(
            "Application", 11, 1001, "Information", DateTime.UtcNow.AddDays(-1),
            "Wininit", "Correcting errors in the Volume Bitmap.", []);
        var older = new TargetedEventRecord(
            "Application", 9, 1001, "Information", DateTime.UtcNow.AddDays(-80),
            "Chkdsk", "Windows has scanned the file system and found no problems.", []);
        var mixed = DriversViewModel.BuildChkdskLine(
            CollectionResult<TargetedEventRecord>.Ok([older, findings], "scope"));
        Assert.Contains("completed with findings", mixed);
        Assert.Contains("2 reports in 90 days", mixed);
        Assert.Contains("Wininit", mixed);
    }

    [Fact]
    public void ReliabilityLine_CoversFailed_Empty_Populated()
    {
        Assert.Contains(
            "could not be read",
            CrashesViewModel.BuildReliabilityLine(
                CollectionResult<ReliabilityRecord>.Fail("s", "r"),
                CollectionResult<ReliabilityMetric>.Ok([], "s")));
        Assert.Contains(
            "kept no records",
            CrashesViewModel.BuildReliabilityLine(
                CollectionResult<ReliabilityRecord>.Ok([], "s"),
                CollectionResult<ReliabilityMetric>.Ok([], "s")));
        var records = CollectionResult<ReliabilityRecord>.Ok(
            [new ReliabilityRecord(DateTime.UtcNow, 1001, "DH", "p", "m")], "s");
        var metrics = CollectionResult<ReliabilityMetric>.Ok(
            [new ReliabilityMetric(DateTime.UtcNow.Date, 7.5)], "s");
        string line = CrashesViewModel.BuildReliabilityLine(records, metrics);
        Assert.Contains("1 record", line);
        Assert.Contains("7.5", line);
    }

    [Fact]
    public void MinidumpLine_CoversFailed_Empty_Populated()
    {
        Assert.Contains(
            "could not be read",
            CrashesViewModel.BuildMinidumpLine(
                CollectionResult<MinidumpReport>.Fail("s", "r")));
        Assert.Contains(
            "No crash dumps",
            CrashesViewModel.BuildMinidumpLine(
                CollectionResult<MinidumpReport>.Ok([], "s")));
        var analyzed = new MinidumpReport(
            "012626-12345-01.dmp", 1_000_000, DateTime.UtcNow,
            0xD1, "DRIVER_IRQL_NOT_LESS_OR_EQUAL", "NETIO", "frames",
            "Analyzed", null);
        string line = CrashesViewModel.BuildMinidumpLine(
            CollectionResult<MinidumpReport>.Ok([analyzed], "s"));
        Assert.Contains("1 crash dump", line);
        Assert.Contains("0xD1", line);

        var missing = analyzed with { Status = "ToolsMissing" };
        string tools = CrashesViewModel.BuildMinidumpLine(
            CollectionResult<MinidumpReport>.Ok([missing], "s"));
        Assert.Contains("0 analyzed", tools);
        Assert.Contains("Debugging Tools not installed", tools);
    }

    [Fact]
    public void TopologyDisk_ShowsDeviceId_OrStatesUnresolved()
    {
        var bare = new DiskTopologyRecord(1, "d", "NVMe", "Healthy", "GPT", 10, true, []);
        var unresolved = DriversViewModel.BuildTopologyDisk(bare);
        Assert.Contains("device ID unresolved", unresolved.Sub);

        var joined = bare with
        {
            PnpDeviceId = @"SCSI\DISK&VEN_NVME&PROD_X\4&1&0&000000",
        };
        var shown = DriversViewModel.BuildTopologyDisk(joined);
        Assert.Contains(@"SCSI\DISK", shown.Sub);
        Assert.DoesNotContain("unresolved", shown.Sub);
    }

    [Fact]
    public void TopologyJoin_ResolvesBootDisk_DeviceId()
    {
        var collected = DiskTopologyCollector.Collect();
        Assert.NotEqual(CollectionStatus.Failed, collected.Status);
        Assert.NotEmpty(collected.Records);
        // The join is evidence, not a guarantee: resolved IDs must be
        // well-formed; unresolved stay null and stated downstream.
        Assert.All(collected.Records, d =>
        {
            if (d.PnpDeviceId is not null)
            {
                Assert.DoesNotContain(" ", d.PnpDeviceId);
            }
        });
    }

    [Fact]
    public void CrashesCollect_Dedupes_OverlappingReads()
    {
        var snapshot = CrashesViewModel.Collect();
        Assert.False(string.IsNullOrWhiteSpace(snapshot.Coverage));
        var keys = snapshot.Rows.Select(r => (r.Anchor.Log, r.Anchor.RecordId)).ToList();
        Assert.Equal(keys.Count, keys.Distinct().Count());
        Assert.True(snapshot.Rows.Count <= 50);
    }
}
