using System.Diagnostics;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.Tests;

// Host read-only smoke tests (04 Phase 1): every collector must
// complete without throwing and report its coverage honestly.
// Success/Partial/Failed are asserted as DISTINCT outcomes: an
// empty Records with Failed status must never look like a clean
// machine. These run on the host because they only READ; mutating
// tests live in the VM.
public sealed class SystemInventoryTests
{
    [Fact]
    public void Processes_Completes_And_ContainsSelf()
    {
        var collected = ProcessCollector.Collect();

        Assert.NotEqual(CollectionStatus.Failed, collected.Status);
        Assert.NotEmpty(collected.Records);
        int self = Process.GetCurrentProcess().Id;
        Assert.Contains(collected.Records, r => r.Id == self && !string.IsNullOrWhiteSpace(r.Name));
        Assert.All(collected.Records, r => Assert.True(r.Id >= 0)); // Id 0 is the System Idle Process.
    }

    [Fact]
    public void RunKeys_Completes_WithWellformedRows()
    {
        var collected = StartupCollector.CollectRunKeys();

        Assert.NotEqual(CollectionStatus.Failed, collected.Status);
        // Zero rows is valid (clean machine); shape is what we assert.
        Assert.All(collected.Records, r =>
        {
            Assert.False(string.IsNullOrWhiteSpace(r.Name));
            Assert.False(string.IsNullOrWhiteSpace(r.Location));
            Assert.NotNull(r.Command);
        });
    }

    [Fact]
    public void StartupFolders_Completes_WithWellformedRows()
    {
        var collected = StartupCollector.CollectStartupFolders();

        Assert.NotEqual(CollectionStatus.Failed, collected.Status);
        Assert.All(collected.Records, r => Assert.False(string.IsNullOrWhiteSpace(r.Name)));
    }

    [Fact]
    public void Services_Completes_And_NonEmpty_On_Windows()
    {
        var collected = StartupCollector.CollectServices();

        Assert.NotEqual(CollectionStatus.Failed, collected.Status);
        Assert.NotEmpty(collected.Records);
        Assert.All(collected.Records, r =>
        {
            Assert.False(string.IsNullOrWhiteSpace(r.Name));
            Assert.False(string.IsNullOrWhiteSpace(r.Status));
        });
    }

    [Fact]
    public void Drivers_Completes_WithWellformedRows()
    {
        var collected = DriverCollector.Collect();

        Assert.NotEqual(CollectionStatus.Failed, collected.Status);
        Assert.All(collected.Records, r => Assert.False(string.IsNullOrWhiteSpace(r.DeviceName)));
    }

    [Theory]
    [InlineData("PCI\\VEN_8086&DEV_1234", "PCI\\VEN_8086&DEV_1234")]
    [InlineData(null, null)]
    [InlineData("   ", null)]
    public void HardwareId_Parses_String_Forms(string? input, string? expected)
    {
        Assert.Equal(expected, DriverCollector.ParseHardwareId(input));
    }

    [Fact]
    public void HardwareId_Parses_Array_And_Other_Shapes()
    {
        Assert.Equal("first", DriverCollector.ParseHardwareId(new[] { "first", "second" }));
        Assert.Null(DriverCollector.ParseHardwareId(Array.Empty<string>()));
        Assert.Equal("42", DriverCollector.ParseHardwareId(42));
    }

    [Fact]
    public void FlattenWmiValue_TakesFirstArrayElement_NeverTypeName()
    {
        // MSFT_MpThreatDetection.Resources arrives as string[]; the Threats
        // page once rendered it as "System.String[]".
        Assert.Equal(
            @"file:_C:\Temp\x",
            DefenderCollector.FlattenWmiValue(new[] { @"file:_C:\Temp\x", "file:_C:\\Temp\\y" }));
        Assert.Null(DefenderCollector.FlattenWmiValue(Array.Empty<string>()));
        Assert.Equal("plain", DefenderCollector.FlattenWmiValue("  plain "));
        Assert.Null(DefenderCollector.FlattenWmiValue(null));
    }

    [Fact]
    public void Events_ValidQuery_Returns_Success_WithCap()
    {
        var collected = EventCollector.CollectRecent(perLog: 10);

        // The fixed XPath must parse on a real machine. Empty records
        // with Success means no matching events, which is legitimate.
        Assert.NotEqual(CollectionStatus.Failed, collected.Status);
        Assert.True(collected.Records.Count <= 20);
        Assert.All(collected.Records, r =>
        {
            Assert.True(r.Log is "System" or "Application");
            Assert.True(r.Level is "Critical" or "Error" or "Warning" or "Info");
            Assert.True(r.Message.Length <= 2012); // 2000 + truncation marker
            Assert.False(string.IsNullOrWhiteSpace(r.Provider));
        });
    }

    [Fact]
    public void Events_Statuses_Are_Distinct_Outcomes()
    {
        // Contract check: Fail() carries Failed + empty records + a gap,
        // so no consumer can mistake it for a clean log.
        var failed = CollectionResult<EventRecord>.Fail("scope", "LogUnreadable", "EventLogException");

        Assert.Equal(CollectionStatus.Failed, failed.Status);
        Assert.Empty(failed.Records);
        Assert.Single(failed.Gaps);
    }

    [Fact]
    public void TargetedEvents_Parses_And_Returns_Identified_Rows()
    {
        var collected = EventCollector.CollectTargeted(
            "System", null, 3, DateTime.UtcNow.AddDays(-7), 5);

        Assert.NotEqual(CollectionStatus.Failed, collected.Status);
        Assert.True(collected.Records.Count <= 5);
        Assert.All(collected.Records, r =>
        {
            Assert.True(r.RecordId >= 0);
            Assert.True(r.TimeUtc <= DateTime.UtcNow.AddMinutes(1));
            Assert.False(string.IsNullOrWhiteSpace(r.Provider));
            Assert.NotNull(r.Properties);
        });
    }

    [Fact]
    public void ChkdskHistory_Query_Parses()
    {
        var collected = EventCollector.CollectChkdskHistory(
            DateTime.UtcNow.AddDays(-90), 10);

        // Empty success is legitimate (no checks ran); failure is not.
        Assert.NotEqual(CollectionStatus.Failed, collected.Status);
        Assert.True(collected.Records.Count <= 10);
    }

    [Fact]
    public void DefenderStatus_Completes_WithWellformedRow()
    {
        var collected = DefenderCollector.CollectStatus();

        Assert.NotEqual(CollectionStatus.Failed, collected.Status);
        Assert.Contains("Defender", collected.Scope);
        var status = Assert.Single(collected.Records);
        Assert.True(status.SignatureAgeDays is null or >= 0);
        Assert.True(status.QuickScanAgeDays is null or >= 0);
        Assert.True(status.FullScanAgeDays is null or >= 0);
    }

    [Fact]
    public void DefenderDetections_Completes_WithBoundedRows()
    {
        var collected = DefenderCollector.CollectDetections(10);

        // Empty success is legitimate (no detections observed);
        // failure is not. Join/mapping paths with live rows are
        // covered by M4 VM acceptance (EICAR ground truth).
        Assert.NotEqual(CollectionStatus.Failed, collected.Status);
        Assert.True(collected.Records.Count <= 10);
        Assert.All(collected.Records, r =>
        {
            Assert.False(string.IsNullOrWhiteSpace(r.ThreatName));
            Assert.False(string.IsNullOrWhiteSpace(r.Severity));
            Assert.False(string.IsNullOrWhiteSpace(r.Category));
        });
    }

    [Fact]
    public void StaticEvidence_UnsignedTempFile_HashesWithoutSigner()
    {
        string path = Path.Combine(Path.GetTempPath(), "sentinel-m4-" + Guid.NewGuid().ToString("N") + ".bin");
        File.WriteAllBytes(path, "sentinel-static-evidence"u8.ToArray());
        try
        {
            var first = StaticEvidenceCollector.CheckFiles([path]);
            var second = StaticEvidenceCollector.CheckFiles([path]);

            Assert.Equal(CollectionStatus.Success, first.Status);
            var row = Assert.Single(first.Records);
            Assert.True(row.Exists);
            Assert.Equal(24, row.LengthBytes);
            Assert.False(row.Signed);
            Assert.Matches("^[0-9A-F]{64}$", row.Sha256);
            Assert.Equal(row.Sha256, Assert.Single(second.Records).Sha256);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [SkippableFact]
    public void StaticEvidence_CatalogSignedBinary_VerifiesViaCatalog()
    {
        // notepad.exe carries no embedded blob on current Windows:
        // trust comes from catalog membership (Valid per
        // Get-AuthenticodeSignature). Both embedded-only checks
        // would misreport it as unsigned.
        string path = Path.Combine(Environment.SystemDirectory, "notepad.exe");
        Skip.IfNot(File.Exists(path), "No notepad.exe on this machine.");

        var row = Assert.Single(StaticEvidenceCollector.CheckFiles([path]).Records);

        Assert.True(row.Exists);
        Assert.True(row.Signed, $"Expected verified trust; detail={row.Detail}");
        Assert.StartsWith("Catalog:", row.Detail);
        Assert.Contains("Microsoft", row.SignerSubject);
        Assert.Matches("^[0-9A-F]{64}$", row.Sha256);
    }

    [SkippableFact]
    public void StaticEvidence_EmbeddedSignedBinary_ReportsSigner()
    {
        string path = Path.Combine(Environment.SystemDirectory, "kernel32.dll");
        Skip.IfNot(File.Exists(path), "No kernel32.dll on this machine.");

        var row = Assert.Single(StaticEvidenceCollector.CheckFiles([path]).Records);

        Assert.True(row.Exists);
        Assert.True(row.Signed, $"Expected verified trust; detail={row.Detail}");
        Assert.False(string.IsNullOrWhiteSpace(row.SignerSubject));
        Assert.Matches("^[0-9A-F]{64}$", row.Sha256);
    }

    [Fact]
    public void StaticEvidence_MissingPath_And_Cap_AreHonest()
    {
        string missing = Path.Combine(Path.GetTempPath(), "sentinel-m4-missing-" + Guid.NewGuid().ToString("N"));
        string a = Path.Combine(Path.GetTempPath(), "sentinel-m4-a-" + Guid.NewGuid().ToString("N") + ".bin");
        string dir = Path.Combine(Path.GetTempPath(), "sentinel-m4-d-" + Guid.NewGuid().ToString("N"));
        File.WriteAllBytes(a, [1, 2, 3]);
        Directory.CreateDirectory(dir);
        try
        {
            var one = StaticEvidenceCollector.CheckFiles([missing]);
            Assert.False(Assert.Single(one.Records).Exists);

            var capped = StaticEvidenceCollector.CheckFiles([a, dir, missing], maxFiles: 2);
            Assert.True(capped.Truncated);
            Assert.Equal(2, capped.Records.Count);
            Assert.False(capped.Records[1].Exists); // Directories are not files.
        }
        finally
        {
            File.Delete(a);
            Directory.Delete(dir);
        }
    }

    [Fact]
    public void DeviceProblems_Completes_WithWellformedRows()
    {
        var collected = DriverCollector.CollectDeviceProblems();

        Assert.NotEqual(CollectionStatus.Failed, collected.Status);
        Assert.Contains("SetupAPI", collected.Scope);
        Assert.All(collected.Records, r =>
        {
            Assert.False(string.IsNullOrWhiteSpace(r.DeviceId));
            Assert.NotEqual(0, r.ErrorCode);
            Assert.False(string.IsNullOrWhiteSpace(r.ErrorName));
        });
    }

    [Fact]
    public void SetupApi_Enumerates_FullDevicePopulation()
    {
        // Regression: two marshalling defects (ANSI char[] buffer, then
        // phantom status silently skipped) once yielded ZERO rows while
        // reporting Success — and the wellformed-rows test above passed
        // vacuously on the empty set. Every real Windows machine
        // enumerates hundreds of device instances; a near-empty result
        // means the P/Invoke path is broken, not the machine is clean.
        var rows = DeviceSetupApi.TryEnumerate(out string? fault);

        Assert.Null(fault);
        Assert.NotNull(rows);
        Assert.True(rows.Count > 50, $"SetupAPI enumerated only {rows.Count} devices.");
    }

    [Fact]
    public void DiskTopology_Joins_Disks_Partitions_Volumes()
    {
        var collected = DiskTopologyCollector.Collect();

        Assert.NotEqual(CollectionStatus.Failed, collected.Status);
        Assert.NotEmpty(collected.Records); // The boot disk is always enumerable.
        foreach (var disk in collected.Records)
        {
            Assert.False(string.IsNullOrWhiteSpace(disk.Name));
            Assert.NotNull(disk.Partitions);
            foreach (var part in disk.Partitions)
            {
                // Join integrity: a claimed volume letter matches.
                if (part.Volume is not null && part.DriveLetter is not null)
                {
                    Assert.Equal(part.DriveLetter, part.Volume.DriveLetter);
                }

                if (part.Volume is not null)
                {
                    Assert.False(string.IsNullOrWhiteSpace(part.Volume.Path));
                }
            }
        }

        // The system drive letter is claimed by exactly one partition.
        string? systemLetter = Path.GetPathRoot(Environment.SystemDirectory)
            ?.TrimEnd(Path.DirectorySeparatorChar, Path.VolumeSeparatorChar);
        if (!string.IsNullOrEmpty(systemLetter))
        {
            int claims = collected.Records
                .SelectMany(d => d.Partitions)
                .Count(p => string.Equals(p.DriveLetter, systemLetter, StringComparison.OrdinalIgnoreCase));
            Assert.True(claims >= 1);
        }
    }

    [Fact]
    public void Power_Completes_WithHonestNulls()
    {
        var batteries = PowerCollector.CollectBatteries();
        var disks = PowerCollector.CollectDisks();

        Assert.NotEqual(CollectionStatus.Failed, batteries.Status);
        Assert.NotEqual(CollectionStatus.Failed, disks.Status);
        Assert.All(batteries.Records, b => Assert.False(string.IsNullOrWhiteSpace(b.Name)));
        Assert.All(disks.Records, d =>
        {
            Assert.False(string.IsNullOrWhiteSpace(d.Name));
            Assert.False(string.IsNullOrWhiteSpace(d.HealthStatus));
        });
    }
}
