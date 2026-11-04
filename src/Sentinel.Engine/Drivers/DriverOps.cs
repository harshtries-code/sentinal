using System.Text.Json;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.Engine.Drivers;

// Live device state for one device instance ID. Present=false means
// the device is gone (unplugged/uninstalled) — every flow refuses.
// Version/Date/HardwareIds are null/empty when the live collectors
// could not observe them — executors refuse rather than guess.
public sealed record DeviceStatus(
    bool Present,
    int ProblemCode,
    string? ProblemName,
    uint StatusFlags,
    string? Name,
    string? DriverVersion,
    string? DriverDate,
    IReadOnlyList<string> HardwareIds);

public sealed record InstallResult(
    bool Success,
    bool RebootRequired,
    string Detail);

public sealed record OemScanSet(
    IReadOnlyList<string> UpdateTitles,
    string RawSummary);

// Approved per-device payload (ActionTarget.AuxJson for Kind
// "device"). Parsed strictly — malformed aux refuses the item.
// For driver_update_from_ladder, Candidate* names the approved
// candidate. For driver_rollback, CandidateSource names the source
// of the BAD version (for the block entry) and TargetPublishedInf +
// Previous* name the restore target.
public sealed record DriverTargetAux(
    string? PreviousPublishedInf,
    string? PreviousVersion,
    string? PreviousDate,
    string? CandidateSource,
    string? CandidateVersion,
    string? CandidateCatalogueId,
    string? TargetPublishedInf,
    string? BadVersion)
{
    public static DriverTargetAux? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<DriverTargetAux>(json);
        }
        catch
        {
            return null;
        }
    }

    public string ToJson() => JsonSerializer.Serialize(this);
}

// D42: every live driver operation behind one seam. Production
// (WindowsDriverOps) shells to pnputil / WUAPI / SetupAPI and runs
// LIVE ONLY in the VM battery; host tests inject scripted fakes.
// No method here takes free-form shell text: INF names are validated
// (`oemN.inf`), WU installs take catalogue IDs from search results,
// DCU takes fixed flags.
public interface IDriverOps
{
    DeviceStatus ReadDevice(string deviceId);

    IReadOnlyList<DriverRecord> EnumInstalledDrivers();

    IReadOnlyList<StorePackage> EnumStore();

    IReadOnlyList<DriverCandidate> SearchWindowsUpdate(
        string deviceId, string? deviceName, IReadOnlyList<string> hardwareIds);

    InstallResult InstallWindowsUpdate(string deviceId, string catalogueId);

    InstallResult InstallStorePackage(string publishedInf);

    OemScanSet ScanOemCatalogue();

    InstallResult ApplyOemCatalogue();

    bool IsNetworkAvailable();
}
