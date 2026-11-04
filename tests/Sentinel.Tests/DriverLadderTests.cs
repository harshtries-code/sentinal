using Sentinel.Engine.Drivers;

namespace Sentinel.Tests;

// D40: the driver source ladder — exactly three steps, per-vendor
// capabilities from 07 Q3, and hardware/signature/version matching.
// Windows Update first, always; unknown vendors get honesty, never
// a guessed catalogue.
public sealed class DriverLadderTests
{
    [Fact]
    public void SourceLadder_HasExactlyThreeSteps_NoStepFour()
    {
        var values = Enum.GetValues<DriverSource>();
        Assert.Equal(3, values.Length);
        Assert.Contains(DriverSource.WindowsUpdate, values);
        Assert.Contains(DriverSource.OemCatalogue, values);
        Assert.Contains(DriverSource.VendorLinkOut, values);
    }

    [Fact]
    public void Vendors_TableContents()
    {
        Assert.Equal(6, OemVendors.All.Count);
        var capable = OemVendors.All.Where(v => v.Capability == OemCapability.UpdateCapable).ToList();
        var dell = Assert.Single(capable);
        Assert.Equal("dell", dell.Id);
        Assert.NotNull(dell.CliPathX64);
        Assert.NotNull(dell.CliPathX86);
        Assert.Contains("ALL", dell.UpdateScopeNote);
        Assert.All(OemVendors.All.Where(v => v.Id != "dell"),
            v => Assert.Equal(OemCapability.LinkOutOnly, v.Capability));
        Assert.All(OemVendors.All, v =>
        {
            Assert.StartsWith("https://", v.SupportUrl);
            Assert.NotEmpty(v.LicenceNote);
        });
    }

    [Theory]
    [InlineData("Dell Inc.", "dell")]
    [InlineData("DELL", "dell")]
    [InlineData("LENOVO", "lenovo")]
    [InlineData("Lenovo", "lenovo")]
    [InlineData("HP", "hp")]
    [InlineData("HP Inc.", "hp")]
    [InlineData("Hewlett-Packard Company", "hp")]
    [InlineData("HPE", "hp")]
    [InlineData("ASUSTeK COMPUTER INC.", null)]
    [InlineData("Apple Inc.", null)]
    [InlineData("PHILIPS", null)]
    [InlineData("Micro-Star International", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void MatchManufacturer_Matrix(string? manufacturer, string? expected)
    {
        Assert.Equal(expected, OemVendors.MatchManufacturer(manufacturer)?.Id);
    }

    [Theory]
    [InlineData("INTEL", "intel")]
    [InlineData("Intel Corporation", "intel")]
    [InlineData("NVIDIA", "nvidia")]
    [InlineData("Advanced Micro Devices, Inc.", "amd")]
    [InlineData("Dell Inc.", "dell")]
    [InlineData("Realtek", null)]
    [InlineData("Microsoft", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void MatchProvider_Matrix(string? provider, string? expected)
    {
        Assert.Equal(expected, OemVendors.MatchProvider(provider)?.Id);
    }

    [Fact]
    public void Resolve_DellWithDcu_FullLadder_OemNotesAllAtOnce()
    {
        var ctx = new OemContext("Dell Inc.", true, @"C:\Program Files\Dell\CommandUpdate\dcu-cli.exe", false);
        var resolution = DriverSourceLadder.Resolve("INTEL", ctx);

        Assert.Equal(DriverSource.WindowsUpdate, resolution.Steps[0].Source);
        var oem = Assert.Single(resolution.Steps, s => s.Source == DriverSource.OemCatalogue);
        Assert.Equal("dell", oem.VendorId);
        Assert.Contains("dcu-cli", oem.Detail);
        Assert.Contains("ALL", oem.Detail);
        Assert.Contains(resolution.Steps, s => s.Source == DriverSource.VendorLinkOut && s.VendorId == "dell");
        Assert.Contains(resolution.Steps, s => s.Source == DriverSource.VendorLinkOut && s.VendorId == "intel");
    }

    [Fact]
    public void Resolve_DellWithoutDcu_NoCatalogue_HonestNote()
    {
        var ctx = new OemContext("Dell Inc.", false, null, false);
        var resolution = DriverSourceLadder.Resolve(null, ctx);

        Assert.DoesNotContain(resolution.Steps, s => s.Source == DriverSource.OemCatalogue);
        Assert.Contains(resolution.Steps, s => s.Source == DriverSource.VendorLinkOut && s.VendorId == "dell");
        Assert.Contains(resolution.Notes, n => n.Contains("not installed"));
    }

    [Fact]
    public void Resolve_Lenovo_LinkOut_TvsuNote()
    {
        var present = new OemContext("LENOVO", false, null, true);
        var r1 = DriverSourceLadder.Resolve(null, present);
        Assert.DoesNotContain(r1.Steps, s => s.Source == DriverSource.OemCatalogue);
        Assert.Contains(r1.Notes, n => n.Contains("unverified"));

        var absent = new OemContext("LENOVO", false, null, false);
        var r2 = DriverSourceLadder.Resolve(null, absent);
        Assert.Contains(r2.Notes, n => n.Contains("link only"));
    }

    [Fact]
    public void Resolve_UnknownVendor_WindowsUpdatePlusGuidance()
    {
        var ctx = new OemContext("Acme Computers", false, null, false);
        var resolution = DriverSourceLadder.Resolve("Realtek", ctx);

        Assert.Single(resolution.Steps);
        Assert.Equal(DriverSource.WindowsUpdate, resolution.Steps[0].Source);
        Assert.Contains(resolution.Notes, n => n.Contains("Acme Computers") && n.Contains("unknown"));
    }

    [Fact]
    public void Resolve_WindowsUpdate_AlwaysFirst()
    {
        var contexts = new[]
        {
            new OemContext("Dell Inc.", true, "x", false),
            new OemContext("LENOVO", false, null, true),
            new OemContext(null, false, null, false),
            new OemContext("HP Inc.", false, null, false),
        };
        foreach (var ctx in contexts)
        {
            var resolution = DriverSourceLadder.Resolve("INTEL", ctx);
            Assert.Equal(DriverSource.WindowsUpdate, resolution.Steps[0].Source);
        }
    }

    [Fact]
    public void Detector_DcuPathPreference()
    {
        string x64 = OemVendors.Dell.CliPathX64!;
        string x86 = OemVendors.Dell.CliPathX86!;
        var both = OemDetector.Detect(() => "Dell", _ => true);
        Assert.True(both.DellDcuInstalled);
        Assert.Equal(x64, both.DellDcuPath);

        var only86 = OemDetector.Detect(() => "Dell", p => p == x86);
        Assert.True(only86.DellDcuInstalled);
        Assert.Equal(x86, only86.DellDcuPath);

        var none = OemDetector.Detect(() => "Dell", _ => false);
        Assert.False(none.DellDcuInstalled);
        Assert.Null(none.DellDcuPath);
    }

    [Fact]
    public void Detector_SafeOnThrow()
    {
        var ctx = OemDetector.Detect(
            () => throw new InvalidOperationException("wmi down"),
            _ => throw new IOException("fs down"));
        Assert.Null(ctx.Manufacturer);
        Assert.False(ctx.DellDcuInstalled);
        Assert.False(ctx.LenovoTvsuPresent);
    }

    [Fact]
    public void Detector_RealManufacturerRead_DoesNotThrow()
    {
        // Read-only host probe: returns the string or null, never throws.
        string? manufacturer = OemDetector.ReadManufacturerWmi();
        Assert.True(manufacturer is null || manufacturer.Length > 0);
    }

    private static DriverCandidate Candidate(
        string version = "15.11.30.14", string? signer = "Microsoft Windows Hardware Compatibility Publisher",
        params string[] hw) =>
        new(DriverSource.WindowsUpdate, null, version, null, signer,
            hw.Length == 0 ? ["PCI\\VEN_8086&DEV_1234"] : hw, null, null);

    [Fact]
    public void Matching_Eligible_HappyPath()
    {
        var verdict = DriverMatching.CheckEligible(
            Candidate("15.11.30.14"), "15.11.30.11",
            ["PCI\\VEN_8086&DEV_1234"]);

        Assert.True(verdict.Eligible);
        Assert.Contains("Newer than installed", verdict.Reason);
    }

    [Fact]
    public void Matching_HardwareMismatch_Refused()
    {
        var verdict = DriverMatching.CheckEligible(
            Candidate(), "15.11.30.11",
            ["PCI\\VEN_10DE&DEV_9999"]);

        Assert.False(verdict.Eligible);
        Assert.Contains("do not match", verdict.Reason);
    }

    [Fact]
    public void Matching_EmptyHardware_NeverBlind()
    {
        var blind = Candidate() with { HardwareIds = [] };
        var verdict = DriverMatching.CheckEligible(blind, "1.0", ["PCI\\VEN_8086&DEV_1234"]);

        Assert.False(verdict.Eligible);
        Assert.Contains("blind", verdict.Reason);
    }

    [Fact]
    public void Matching_MissingSigner_Refused()
    {
        var unsigned = Candidate(signer: null);
        var verdict = DriverMatching.CheckEligible(unsigned, "1.0", ["PCI\\VEN_8086&DEV_1234"]);

        Assert.False(verdict.Eligible);
        Assert.Contains("signer", verdict.Reason);
    }

    [Theory]
    [InlineData("15.11.30.14", "15.11.30.14", "Already on")]
    [InlineData("15.11.30.11", "15.11.30.14", "older than installed")]
    public void Matching_NotNewer_Refused(string candidate, string installed, string word)
    {
        var verdict = DriverMatching.CheckEligible(
            Candidate(candidate), installed, ["PCI\\VEN_8086&DEV_1234"]);

        Assert.False(verdict.Eligible);
        Assert.Contains(word, verdict.Reason);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Matching_UnversionedCandidate_RefusedBlind(string version)
    {
        var verdict = DriverMatching.CheckEligible(
            Candidate(version), "15.11.30.11", ["PCI\\VEN_8086&DEV_1234"]);

        Assert.False(verdict.Eligible);
        Assert.Contains("blind install", verdict.Reason);
    }

    [Fact]
    public void Matching_UnknownInstalled_NewerWins()
    {
        var verdict = DriverMatching.CheckEligible(
            Candidate("1.0"), null, ["PCI\\VEN_8086&DEV_1234"]);

        Assert.True(verdict.Eligible);
    }

    [Fact]
    public void Matching_BlockedVersion_NeverOfferedAgain()
    {
        var candidate = Candidate("15.11.30.14");
        var blocked = new HashSet<string> { DriverMatching.BlockKey(candidate) };
        var verdict = DriverMatching.CheckEligible(
            candidate, "15.11.30.11", ["PCI\\VEN_8086&DEV_1234"], blocked);

        Assert.False(verdict.Eligible);
        Assert.Contains("not offered again", verdict.Reason);
    }

    [Fact]
    public void BlockKey_Format()
    {
        Assert.Equal("WindowsUpdate|15.11.30.14", DriverMatching.BlockKey(Candidate("15.11.30.14")));
    }

    [Theory]
    [InlineData("15.11.30.14", "15.11.30.11", 1)]
    [InlineData("10.1.36.7", "10.1.36.70", -1)]
    // .NET Version semantics: missing components sort below zeros.
    // Conservative for the ladder (a shorter candidate never counts
    // as newer than a longer installed version).
    [InlineData("1.0", "1.0.0.0", -1)]
    [InlineData("1.0.0.0", "1.0", 1)]
    [InlineData("05/19/2026 15.11.30.14", "15.11.30.14", 0)]
    [InlineData(null, "1.0", -1)]
    [InlineData("1.0", null, 1)]
    public void CompareVersions_Matrix(string? a, string? b, int expected)
    {
        Assert.Equal(expected, Math.Sign(DriverMatching.CompareVersions(a, b, out bool fallback)));
        Assert.False(fallback);
    }

    [Fact]
    public void CompareVersions_BothNull_Equal()
    {
        Assert.Equal(0, DriverMatching.CompareVersions(null, null, out bool fallback));
        Assert.False(fallback);
    }

    [Fact]
    public void CompareVersions_Unparseable_FallsBackOrdinal()
    {
        Assert.Equal(-1, Math.Sign(DriverMatching.CompareVersions("abc", "abd", out bool fallback)));
        Assert.True(fallback);
    }

    [Fact]
    public void Normalize_PnputilForm()
    {
        Assert.Equal("15.11.30.14", DriverMatching.Normalize("05/19/2026 15.11.30.14"));
        Assert.Equal("10.1.36.7", DriverMatching.Normalize("  10.1.36.7  "));
        Assert.Equal("abc", DriverMatching.Normalize("abc"));
    }
}
