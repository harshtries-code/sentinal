namespace Sentinel.Engine.SystemInventory;

// P28: the device-diagnostics boundary, recorded as data instead
// of tribal knowledge. Every domain Sentinel touches (or refuses
// to touch) on the Drivers page has exactly one verdict here, and
// the page prints the summary line verbatim.
public enum DeviceDiagnosticTier
{
    // Read live and shown (SetupAPI/WMI).
    Observed,

    // Real, but Sentinel only reads point-in-time state and misses
    // changes between refreshes. Stated, not hidden.
    PointInTimeBlindSpot,

    // No Windows API exposes this; only the OEM's tools can see it.
    // Sentinel records symptoms, never verdicts.
    UndiagnosableWithoutVendorTools,

    // Deliberately not attempted: no sensor access, no vendor SDK,
    // or no software signal exists at all.
    GatedUnsupported,
}

public sealed record DeviceDomainVerdict(
    string Domain,
    DeviceDiagnosticTier Tier,
    string Detail);

// P28: which PnP properties Sentinel reads per device, and which
// it deliberately does not. The Read set must match the live
// collectors' queries (pinned by test); the NotRead set names the
// reason so "missing" reads as a decision, not an oversight.
public sealed record PnpPropertyCoverage(
    string Property,
    bool Read,
    string SourceOrReason);

// P28: what Sentinel may DO to a device, per class. There is
// exactly one tier today: observe. Tier 1 (OS-exposed toggles
// like enable/disable) needs an E30 action template, a vendor
// procedure, and a restore point — none of which exist yet — so
// every class maps to ObserveOnly with the requirement stated.
public enum DeviceFixupTier
{
    ObserveOnly,
}

public static class DeviceCapabilityMatrix
{
    public static readonly IReadOnlyList<DeviceDomainVerdict> Domains =
    [
        new(
            "PnP device inventory",
            DeviceDiagnosticTier.Observed,
            "SetupAPI device status (Device Manager source) plus WMI driver properties."),
        new(
            "Hot-plug events (Win32_DeviceChange)",
            DeviceDiagnosticTier.PointInTimeBlindSpot,
            "Sentinel does not listen for device arrival/removal; the list is a point-in-time read and " +
            "misses devices plugged in between refreshes. No kernel watcher by design."),
        new(
            "CMOS battery",
            DeviceDiagnosticTier.UndiagnosableWithoutVendorTools,
            "No Windows API reports CMOS state; a resetting clock is the only symptom Sentinel can note."),
        new(
            "Fans",
            DeviceDiagnosticTier.UndiagnosableWithoutVendorTools,
            "No standard API exposes fan speed or curves; vendor tools own them."),
        new(
            "PSU",
            DeviceDiagnosticTier.UndiagnosableWithoutVendorTools,
            "No API exposes PSU health; unexpected shutdowns surface as Event 41, never as a PSU verdict."),
        new(
            "Beep codes",
            DeviceDiagnosticTier.UndiagnosableWithoutVendorTools,
            "Beep meanings are vendor/BIOS-specific; record them, never decode them."),
        new(
            "Temperatures",
            DeviceDiagnosticTier.GatedUnsupported,
            "Thermal probes are out of scope without vendor SDKs; Sentinel never reads or acts on temperature."),
        new(
            "Power rails and voltages",
            DeviceDiagnosticTier.GatedUnsupported,
            "No standard sensor API; out of scope by design."),
        new(
            "Physical damage",
            DeviceDiagnosticTier.GatedUnsupported,
            "No software can inspect hardware; bulging capacitors and burnt smells belong to a technician."),
    ];

    public static readonly IReadOnlyList<PnpPropertyCoverage> PnpProperties =
    [
        new("DeviceID", true, "SetupAPI enumerate + Win32_PnPEntity"),
        new("DeviceName", true, "SetupAPI registry properties; WMI name fallback"),
        new("ProblemCode", true, "SetupAPI status flags (Device Manager source)"),
        new("StatusFlags", true, "SetupAPI status flags"),
        new("DriverVersion", true, "Win32_PnPSignedDriver"),
        new("DriverDate", true, "Win32_PnPSignedDriver"),
        new("Signer", true, "Win32_PnPSignedDriver"),
        new("HardwareID", true, "Win32_PnPSignedDriver, best-effort"),
        new("ResourceAssignments", false, "IRQ/DMA/port ranges have no consumer in any Sentinel decision"),
        new("PowerCapabilities", false, "No power-policy consumer; would need per-device semantics review"),
        new("DevicePropertyKeys", false, "Full DEVPKEY enumeration is unbounded; read per need only"),
        new("DriverFiles", false, "File-level driver inventory belongs to the signed-pack work (T56)"),
    ];

    public static DeviceFixupTier TierFor(string? deviceClass)
    {
        _ = deviceClass;
        return DeviceFixupTier.ObserveOnly;
    }

    public const string TierDetail =
        "Every device class is observe-only: automated fixup needs an approved action template, " +
        "a vendor procedure, and a restore point, and none exist yet.";

    // Printed verbatim on the Drivers page (boundaries line).
    public const string BoundariesLine =
        "Cannot check: CMOS, fans, PSU, beep codes, temperatures, voltages, or physical damage " +
        "(needs vendor tools). Device list is point-in-time — hot-plugged devices between refreshes are missed.";
}
