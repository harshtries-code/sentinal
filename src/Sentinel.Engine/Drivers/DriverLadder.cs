using System.Management;
using System.Runtime.InteropServices;

namespace Sentinel.Engine.Drivers;

// What the ladder detected on this machine. Built by OemDetector
// (read-only); tests construct it directly.
public sealed record OemContext(
    string? Manufacturer,
    bool DellDcuInstalled,
    string? DellDcuPath,
    bool LenovoTvsuPresent);

// One rung of the resolved ladder: which source, for which vendor,
// and the honest detail line the UI shows.
public sealed record LadderStep(
    DriverSource Source,
    string? VendorId,
    string Detail);

public sealed record LadderResolution(
    IReadOnlyList<LadderStep> Steps,
    IReadOnlyList<string> Notes);

// D40: read-only OEM detection. Manufacturer from WMI (same source
// Device Manager-class tools use); tool presence from well-known
// install paths (existence only — nothing is launched by detection).
public static class OemDetector
{
    public static OemContext Detect(
        Func<string?>? manufacturerReader = null,
        Func<string, bool>? fileExists = null)
    {
        manufacturerReader ??= ReadManufacturerWmi;
        fileExists ??= File.Exists;

        string? manufacturer = SafeRead(manufacturerReader);
        var dell = OemVendors.Dell;
        string? dcuPath = null;
        if (dell.CliPathX64 is not null && SafeExists(fileExists, dell.CliPathX64))
        {
            dcuPath = dell.CliPathX64;
        }
        else if (dell.CliPathX86 is not null && SafeExists(fileExists, dell.CliPathX86))
        {
            dcuPath = dell.CliPathX86;
        }

        // TVSU presence is recorded for the note only — Lenovo stays
        // link-out until its CLI is verified on Lenovo hardware.
        bool tvsu = SafeExists(fileExists, @"C:\Program Files\Lenovo\System Update\tvsu.exe") ||
            SafeExists(fileExists, @"C:\Program Files (x86)\Lenovo\System Update\tvsu.exe");

        return new OemContext(manufacturer, dcuPath is not null, dcuPath, tvsu);
    }

    public static string? ReadManufacturerWmi()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Manufacturer FROM Win32_ComputerSystem");
            foreach (var obj in searcher.Get())
            {
                using (obj)
                {
                    try
                    {
                        string? value = obj["Manufacturer"]?.ToString()?.Trim();
                        if (!string.IsNullOrWhiteSpace(value))
                        {
                            return value;
                        }
                    }
                    catch
                    {
                        return null;
                    }
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or COMException)
        {
        }

        return null;
    }

    private static string? SafeRead(Func<string?> reader)
    {
        try
        {
            return reader();
        }
        catch
        {
            return null;
        }
    }

    private static bool SafeExists(Func<string, bool> exists, string path)
    {
        try
        {
            return exists(path);
        }
        catch
        {
            return false;
        }
    }
}

// D40: the source ladder as code (05 §5). Windows Update first,
// always. The OEM catalogue rung appears only for an update-capable
// vendor whose tool is actually installed. Link-outs name official
// pages. Unknown vendors fall back to Windows Update + guidance —
// the ladder never guesses a vendor, never invents a step 4.
public static class DriverSourceLadder
{
    public static LadderResolution Resolve(string? deviceProvider, OemContext context)
    {
        var steps = new List<LadderStep>();
        var notes = new List<string>();

        steps.Add(new LadderStep(DriverSource.WindowsUpdate, null,
            "Windows Update — checked first for every device."));

        var machine = OemVendors.MatchManufacturer(context.Manufacturer);
        if (machine?.Capability == OemCapability.UpdateCapable &&
            machine.Id == OemVendors.Dell.Id &&
            context.DellDcuInstalled)
        {
            steps.Add(new LadderStep(DriverSource.OemCatalogue, machine.Id,
                "Dell Command Update catalogue (dcu-cli found at '" + context.DellDcuPath +
                "'). Applies ALL pending Dell updates at once — confirmed as a set."));
        }
        else if (machine?.Capability == OemCapability.UpdateCapable)
        {
            notes.Add(
                $"{machine.DisplayName} catalogue tools are not installed — catalogue updates are unavailable. " +
                "Windows Update still applies.");
        }

        if (machine is not null && machine.Capability == OemCapability.LinkOutOnly)
        {
            notes.Add(TvsuNote(machine, context));
        }

        var component = OemVendors.MatchProvider(deviceProvider);
        var linked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (machine is not null)
        {
            linked.Add(machine.Id);
            steps.Add(new LadderStep(DriverSource.VendorLinkOut, machine.Id,
                $"Official {machine.DisplayName} support page (link only — Sentinel does not download it)."));
        }

        if (component is not null && linked.Add(component.Id))
        {
            steps.Add(new LadderStep(DriverSource.VendorLinkOut, component.Id,
                $"Official {component.DisplayName} download page (link only — Sentinel does not download it)."));
        }

        if (machine is null)
        {
            notes.Add(
                "Machine vendor not recognized" +
                (string.IsNullOrWhiteSpace(context.Manufacturer)
                    ? "."
                    : $" ('{context.Manufacturer}').") +
                " Windows Update applies; no vendor catalogue is offered for an unknown vendor.");
        }

        return new LadderResolution(steps, notes);
    }

    private static string TvsuNote(OemVendor machine, OemContext context)
    {
        if (machine.Id == OemVendors.Lenovo.Id && context.LenovoTvsuPresent)
        {
            return "Lenovo System Update is present but its command line is unverified — " +
                "link-out until proven on Lenovo hardware (07 Q3).";
        }

        return $"{machine.DisplayName} has no verified scriptable updater in v1 — official page link only.";
    }
}
