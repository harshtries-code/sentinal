using Sentinel.Engine.Actions;
using Sentinel.Engine.Drivers;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.Tests;

// D41: elevated-process elevation model, restore-point capability,
// pnputil parsing, and previous-driver identity. Live restore-point
// creation and live driver changes run in the VM battery only —
// everything here is pure logic plus read-only host probes.
public sealed class DriverCapabilityTests
{
    [Fact]
    public void Elevation_Clean_Unelevated_MayRun()
    {
        var clean = ActionRegistry.Find("clean_items_to_vault")!;
        Assert.True(ElevationPolicy.TemplateMayRun(clean, isElevated: false, out string reason));
        Assert.Empty(reason);
    }

    [Fact]
    public void Elevation_Driver_Unelevated_RefusedWithRelaunchReason()
    {
        var driver = ActionRegistry.Find("driver_update_from_ladder")!;
        Assert.False(ElevationPolicy.TemplateMayRun(driver, isElevated: false, out string reason));
        Assert.Contains("administrator", reason);
        Assert.Contains("relaunch", reason);
    }

    [Fact]
    public void Elevation_Driver_Elevated_MayRun()
    {
        var update = ActionRegistry.Find("driver_update_from_ladder")!;
        var rollback = ActionRegistry.Find("driver_rollback")!;
        var scan = ActionRegistry.Find("defender_scan")!;
        Assert.True(ElevationPolicy.TemplateMayRun(update, isElevated: true, out _));
        Assert.True(ElevationPolicy.TemplateMayRun(rollback, isElevated: true, out _));
        Assert.True(ElevationPolicy.TemplateMayRun(scan, isElevated: true, out _));
    }

    [Fact]
    public void Elevation_LiveCheck_DoesNotThrow()
    {
        // Either answer is fine on any host; throwing is not.
        bool elevated = ElevationPolicy.IsProcessElevated();
        Assert.True(elevated || !elevated);
    }

    [Fact]
    public void RestoreCapability_DisabledSr_Refuses()
    {
        var capability = RestorePointManager.CheckCapability(() => 1);

        Assert.False(capability.Capable);
        Assert.Contains("turned off", capability.Reason);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(null)]
    public void RestoreCapability_EnabledOrMissing_Capable(int? value)
    {
        var capability = RestorePointManager.CheckCapability(() => value);

        Assert.True(capability.Capable);
    }

    [Fact]
    public void RestoreCapability_ReadFailure_FailsClosed()
    {
        var capability = RestorePointManager.CheckCapability(
            () => throw new UnauthorizedAccessException("locked"));

        Assert.False(capability.Capable);
        Assert.Contains("could not be determined", capability.Reason);
    }

    [Fact]
    public void RestoreCapability_RealRegistryRead_DoesNotThrow()
    {
        int? value = RestorePointManager.ReadDisableSr();
        Assert.True(value is null || value >= 0);
    }

    private sealed class FakeSr : ISrClient
    {
        public long? Seq { get; set; } = 42;

        public string? BeginError { get; set; }

        public string? EndError { get; set; }

        public List<string> Begun { get; } = [];

        public (long? Sequence, string? Error) Begin(string description)
        {
            Begun.Add(description);
            return BeginError is null ? (Seq, null) : (null, BeginError);
        }

        public string? End(long sequence) => EndError;
    }

    [Fact]
    public void RestorePoint_BeginEnd_RoundTrip()
    {
        var sr = new FakeSr();
        var (seq, error) = RestorePointManager.Begin(sr, "Sentinel driver update");

        Assert.Equal(42, seq);
        Assert.Null(error);
        Assert.Null(RestorePointManager.End(sr, 42));
        Assert.Equal(["Sentinel driver update"], sr.Begun);
    }

    [Fact]
    public void RestorePoint_BeginFailure_MapsError()
    {
        var sr = new FakeSr { BeginError = "VSS timeout" };
        var (seq, error) = RestorePointManager.Begin(sr, "x");

        Assert.Null(seq);
        Assert.Equal("VSS timeout", error);
    }

    [Fact]
    public void RestorePoint_ClientThrow_MapsError()
    {
        var sr = new ThrowingSr();
        var (seq, error) = RestorePointManager.Begin(sr, "x");

        Assert.Null(seq);
        Assert.Contains("InvalidOperationException", error);
        Assert.Contains("boom", RestorePointManager.End(sr, 1));
    }

    private sealed class ThrowingSr : ISrClient
    {
        public (long? Sequence, string? Error) Begin(string description) =>
            throw new InvalidOperationException("boom");

        public string? End(long sequence) => throw new InvalidOperationException("boom");
    }

    // Captured live from `pnputil /enum-drivers` on host, 2026-11-04
    // (regular package + extension package with Extension ID).
    private const string PnpSample = """
        Microsoft PnP Utility

        Published Name:     oem102.inf
        Original Name:      acpivpc.inf
        Provider Name:      Lenovo
        Class Name:         System
        Class GUID:         {4d36e97d-e325-11ce-bfc1-08002be10318}
        Driver Version:     05/19/2026 15.11.30.14
        Signer Name:        Microsoft Windows Hardware Compatibility Publisher

        Published Name:     oem93.inf
        Original Name:      aispeechapoext.inf
        Provider Name:      AISpeech Technology Co.,Ltd
        Class Name:         Extension
        Class GUID:         {e2f84ce7-8efa-411c-aa69-97454ca4cb57}
        Extension ID:       {f8e3abd3-d388-4af9-acff-a0714b1b1294}
        Driver Version:     11/13/2025 1.0.1.12
        Signer Name:        Microsoft Windows Hardware Compatibility Publisher

        """;

    [Fact]
    public void PnpParser_TwoEntries()
    {
        var packages = PnpUtilParser.ParseEnumDrivers(PnpSample);

        Assert.Equal(2, packages.Count);
        Assert.Equal("oem102.inf", packages[0].PublishedName);
        Assert.Equal("acpivpc.inf", packages[0].OriginalName);
        Assert.Equal("Lenovo", packages[0].Provider);
        Assert.Equal("System", packages[0].ClassName);
        Assert.Equal("{4d36e97d-e325-11ce-bfc1-08002be10318}", packages[0].ClassGuid);
        Assert.Equal("05/19/2026 15.11.30.14", packages[0].Version);
        Assert.Equal("Microsoft Windows Hardware Compatibility Publisher", packages[0].Signer);
        Assert.Null(packages[0].ExtensionId);
        Assert.Equal("oem93.inf", packages[1].PublishedName);
        Assert.Equal("{f8e3abd3-d388-4af9-acff-a0714b1b1294}", packages[1].ExtensionId);
    }

    [Fact]
    public void PnpParser_SkipsHeader_BlockWithoutPublished_Skipped()
    {
        const string text = """
            Microsoft PnP Utility

            Original Name:      orphan.inf
            Provider Name:      Nobody

            Published Name:     oem1.inf
            Driver Version:     01/01/2024 2.0

            """;
        var packages = PnpUtilParser.ParseEnumDrivers(text);

        var single = Assert.Single(packages);
        Assert.Equal("oem1.inf", single.PublishedName);
        Assert.Null(single.Provider);
    }

    [Fact]
    public void PnpParser_Empty_YieldsEmpty()
    {
        Assert.Empty(PnpUtilParser.ParseEnumDrivers(string.Empty));
        Assert.Empty(PnpUtilParser.ParseEnumDrivers("Microsoft PnP Utility\n"));
    }

    private static DriverRecord InstalledRow(
        string device = "Lenovo ACPI Virtual Power Controller",
        string? version = "15.11.30.14",
        string? date = "20260519000000.000000-000") =>
        new(DeviceName: device, DriverVersion: version, DriverDate: date,
            Signer: "Microsoft Windows Hardware Compatibility Publisher",
            Status: "OK", HardwareId: @"ACPI\VEN_LEN&DEV_0001");

    [Fact]
    public void Identity_HappyPath_LinksStorePackage()
    {
        var store = PnpUtilParser.ParseEnumDrivers(PnpSample);

        var (identity, failure) = DriverIdentityCapture.MatchStorePackage(
            "ACPI\\VEN_LEN&DEV_0001\\0", @"ACPI\VEN_LEN&DEV_0001",
            InstalledRow(), store);

        Assert.Null(failure);
        Assert.NotNull(identity);
        Assert.Equal("oem102.inf", identity.PublishedInf);
        Assert.Equal("acpivpc.inf", identity.OriginalInf);
        Assert.Equal("Lenovo", identity.Provider);
    }

    [Fact]
    public void Identity_NoMatch_RefusesWithoutRollbackTarget()
    {
        var store = PnpUtilParser.ParseEnumDrivers(PnpSample);

        var (identity, failure) = DriverIdentityCapture.MatchStorePackage(
            "dev", null, InstalledRow(version: "99.0"), store);

        Assert.Null(identity);
        Assert.NotNull(failure);
        Assert.Contains("rollback target", failure);
    }

    [Fact]
    public void Identity_DateMismatch_Refuses()
    {
        var store = PnpUtilParser.ParseEnumDrivers(PnpSample);

        var (identity, failure) = DriverIdentityCapture.MatchStorePackage(
            "dev", null, InstalledRow(date: "20200101000000.000000-000"), store);

        Assert.Null(identity);
        Assert.Contains("rollback target", failure);
    }

    [Fact]
    public void Identity_Ambiguous_Refuses()
    {
        var store = new[]
        {
            new StorePackage("oem1.inf", "a.inf", "VendorA", null, null, "1.0", "S", null),
            new StorePackage("oem2.inf", "b.inf", "VendorB", null, null, "1.0", "S", null),
        };
        var row = InstalledRow(device: "Mystery Device", version: "1.0", date: null);

        var (identity, failure) = DriverIdentityCapture.MatchStorePackage("dev", null, row, store);

        Assert.Null(identity);
        Assert.Contains("ambiguous", failure);
    }

    [Fact]
    public void Identity_TieBreak_ByProviderHint()
    {
        var store = new[]
        {
            new StorePackage("oem1.inf", "a.inf", "Intel Corporation", null, null, "1.0", "S", null),
            new StorePackage("oem2.inf", "b.inf", "FooCorp", null, null, "1.0", "S", null),
        };
        var row = InstalledRow(device: "Intel(R) Wi-Fi 6", version: "1.0", date: null);

        var (identity, failure) = DriverIdentityCapture.MatchStorePackage("dev", null, row, store);

        Assert.Null(failure);
        Assert.Equal("oem1.inf", identity!.PublishedInf);
    }

    [Fact]
    public void Identity_UnparseableDate_Ignored()
    {
        var store = PnpUtilParser.ParseEnumDrivers(PnpSample);

        var (identity, failure) = DriverIdentityCapture.MatchStorePackage(
            "dev", null, InstalledRow(date: "garbage"), store);

        Assert.Null(failure);
        Assert.Equal("oem102.inf", identity!.PublishedInf);
    }

    [Theory]
    [InlineData(0u, false)]
    [InlineData(0x00000200u, true)]
    [InlineData(0x00000201u, true)]
    [InlineData(0x00000001u, false)]
    public void DeviceNodeFlags_NeedRestart(uint status, bool expected)
    {
        Assert.Equal(0x00000200u, DeviceNodeFlags.NeedRestart);
        Assert.Equal(expected, DeviceNodeFlags.NeedsRestart(status));
    }
}
