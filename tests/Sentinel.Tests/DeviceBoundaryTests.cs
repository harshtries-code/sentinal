using Sentinel.App.ViewModels;
using Sentinel.Engine.Agent;
using Sentinel.Engine.Policy;
using Sentinel.Engine.SystemInventory;
using Sentinel.Store;

namespace Sentinel.Tests;

// P28: device/protected-path inspection boundaries — the pinned
// verdicts for every domain Sentinel refuses to diagnose, the
// vendor-protected allowlist (never deleted, still inspectable),
// and the NeverTouch separation (protection from action only).
public sealed class DeviceBoundaryTests : IDisposable
{
    private readonly string _dir;

    public DeviceBoundaryTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "sentinel-p28-" + Guid.NewGuid().ToString("N"));
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

    [Fact]
    public void Matrix_PinsEveryP28Domain()
    {
        var tiers = DeviceCapabilityMatrix.Domains.ToDictionary(d => d.Domain, d => d.Tier);

        Assert.Equal(DeviceDiagnosticTier.Observed, tiers["PnP device inventory"]);
        Assert.Equal(DeviceDiagnosticTier.PointInTimeBlindSpot, tiers["Hot-plug events (Win32_DeviceChange)"]);
        Assert.Equal(DeviceDiagnosticTier.UndiagnosableWithoutVendorTools, tiers["CMOS battery"]);
        Assert.Equal(DeviceDiagnosticTier.UndiagnosableWithoutVendorTools, tiers["Fans"]);
        Assert.Equal(DeviceDiagnosticTier.UndiagnosableWithoutVendorTools, tiers["PSU"]);
        Assert.Equal(DeviceDiagnosticTier.UndiagnosableWithoutVendorTools, tiers["Beep codes"]);
        Assert.Equal(DeviceDiagnosticTier.GatedUnsupported, tiers["Temperatures"]);
        Assert.Equal(DeviceDiagnosticTier.GatedUnsupported, tiers["Power rails and voltages"]);
        Assert.Equal(DeviceDiagnosticTier.GatedUnsupported, tiers["Physical damage"]);

        foreach (var domain in DeviceCapabilityMatrix.Domains)
        {
            Assert.False(string.IsNullOrWhiteSpace(domain.Detail));
        }
    }

    [Fact]
    public void BoundariesLine_NamesEveryLimit()
    {
        string line = DeviceCapabilityMatrix.BoundariesLine;
        foreach (string word in new[] { "CMOS", "fans", "PSU", "beep", "temperature", "physical", "point-in-time" })
        {
            Assert.Contains(word, line, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void PnpCoverage_MatchesLiveCollectorQueries()
    {
        var read = DeviceCapabilityMatrix.PnpProperties
            .Where(p => p.Read)
            .Select(p => p.Property)
            .ToHashSet(StringComparer.Ordinal);
        foreach (string field in new[]
            {
                "DeviceID", "DeviceName", "ProblemCode", "StatusFlags",
                "DriverVersion", "DriverDate", "Signer", "HardwareID",
            })
        {
            Assert.Contains(field, read);
        }

        foreach (var entry in DeviceCapabilityMatrix.PnpProperties)
        {
            Assert.False(string.IsNullOrWhiteSpace(entry.SourceOrReason));
        }
    }

    [Fact]
    public void FixupTier_AlwaysObserveOnly()
    {
        foreach (string? cls in new string?[] { null, "", "Display", "Net", "USB", "System", "SCSIAdapter", "garbage" })
        {
            Assert.Equal(DeviceFixupTier.ObserveOnly, DeviceCapabilityMatrix.TierFor(cls));
        }

        Assert.Contains("restore point", DeviceCapabilityMatrix.TierDetail);
    }

    [Theory]
    [InlineData(@"C:\System Volume Information", true)]
    [InlineData(@"C:\System Volume Information\tracking.log", true)]
    [InlineData(@"C:\System Volume Information\", true)]
    [InlineData(@"c:\system volume information", true)]
    [InlineData(@"D:\Recovery", true)]
    [InlineData(@"D:\Recovery\Logs\boot.log", true)]
    [InlineData(@"E:\$WinREAgent", true)]
    [InlineData(@"C:\Windows\CSC", true)]
    [InlineData(@"C:\Windows\CSC\v2.0.6", true)]
    [InlineData(@"C:\RecoveryX", false)]
    [InlineData(@"C:\Windows\CSCX", false)]
    [InlineData(@"C:\Users\me\file.txt", false)]
    [InlineData(@"C:\Windows\System32\drivers\acpi.sys", false)]
    [InlineData("", false)]
    [InlineData("???", false)]
    [InlineData("System Volume Information", false)]
    public void VendorProtected_Matching(string path, bool expected)
    {
        Assert.Equal(expected, VendorProtected.IsVendorProtected(path));
        Assert.Equal(expected, VendorProtected.ReasonFor(path) is not null);
    }

    [Fact]
    public void VendorProtected_Reason_IsWorded()
    {
        string? reason = VendorProtected.ReasonFor(@"D:\Recovery\WinRE.wim");
        Assert.NotNull(reason);
        Assert.StartsWith("Vendor-protected: Recovery", reason);
    }

    [Fact]
    public void Classifier_VendorProtected_IsNever()
    {
        var classifier = new RiskClassifier();
        var verdict = classifier.Classify(
            new Fingerprint(@"C:\System Volume Information\tracking.log", 100, DateTime.UtcNow.Ticks, null, 0),
            DateTime.UtcNow);

        Assert.Equal(RiskTier.Never, verdict.Tier);
        Assert.Contains("N-vendorprotected", verdict.RuleIds);
    }

    [Fact]
    public void Classifier_NeverTouch_StillFirst()
    {
        string guarded = Path.Combine(_dir, "guarded");
        Directory.CreateDirectory(guarded);
        string file = Path.Combine(guarded, "notes.txt");
        File.WriteAllText(file, "x");
        var classifier = new RiskClassifier([guarded]);
        var verdict = classifier.Classify(
            new Fingerprint(file, 1, DateTime.UtcNow.Ticks, null, 0),
            DateTime.UtcNow);

        Assert.Equal(RiskTier.Never, verdict.Tier);
        Assert.Contains("N-neverlist", verdict.RuleIds);
    }

    [Fact]
    public void Broker_InspectionIgnoresNeverTouch()
    {
        // P28 separation proof: the broker's resolver takes no
        // NeverTouch input at all, so a protected-from-ACTION path
        // still resolves for warranted in-scope inspection.
        string file = Path.Combine(_dir, "sight.txt");
        File.WriteAllText(file, "visible");
        using var audit = new AgentStore(Path.Combine(_dir, "agent.db"));
        var broker = new ToolBroker(audit);
        var scope = new InvestigationScope("inv-p28", [_dir]);
        string id = broker.MintFileId(file);

        Assert.Equal(file, broker.ResolveScopedPath(scope, id, "file_id"));
    }

    [Fact]
    public void DriversViewModel_Boundaries_MatchesMatrix()
    {
        var vm = new DriversViewModel(() => new PassportDb(Path.Combine(_dir, "passport.db")));

        Assert.Equal(DeviceCapabilityMatrix.BoundariesLine, vm.Boundaries);
    }
}
