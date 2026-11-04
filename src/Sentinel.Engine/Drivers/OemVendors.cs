namespace Sentinel.Engine.Drivers;

// 05 §5: the driver source ladder. EXACTLY three steps — there is
// no step 4. Unsigned or mirror-site drivers are never fetched,
// never installed: every step below is a signed first-party channel.
public enum DriverSource
{
    // Source #1 for every device, always offered first.
    WindowsUpdate,

    // The machine vendor's signed catalogue, only when the vendor is
    // detected AND update-capable AND its tool is installed (Dell
    // DCU in v1). Lenovo TVSU stays link-out until verified.
    OemCatalogue,

    // An official vendor page LINK shown to the user. Sentinel does
    // not download it, does not script it, does not vouch for which
    // download the user picks once they leave the app.
    VendorLinkOut,
}

public enum OemCapability
{
    // Sentinel can query and apply through the vendor's tool.
    UpdateCapable,

    // Official page link only.
    LinkOutOnly,
}

public sealed record OemVendor(
    string Id,
    string DisplayName,
    OemCapability Capability,
    string DetectionNote,
    string? CliPathX64,
    string? CliPathX86,
    string SupportUrl,
    string LicenceNote,
    string UpdateScopeNote);

// D40: the per-vendor table (07 Q3, preserved). Capabilities change
// only with a verified CLI + an owner-approved edit here.
public static class OemVendors
{
    public static readonly OemVendor Dell = new(
        "dell", "Dell", OemCapability.UpdateCapable,
        "Manufacturer contains 'Dell' AND dcu-cli.exe present",
        @"C:\Program Files\Dell\CommandUpdate\dcu-cli.exe",
        @"C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe",
        "https://www.dell.com/support/home",
        "Dell proprietary; ships with Dell Command Update (free, Dell machines).",
        "DCU applies ALL pending updates at once (/applyUpdates) — no per-device select. " +
        "Sentinel confirms the whole set explicitly, never silently.");

    public static readonly OemVendor Lenovo = new(
        "lenovo", "Lenovo", OemCapability.LinkOutOnly,
        "Manufacturer contains 'Lenovo'; TVSU CLI unverified — link-out until proven on Lenovo hardware",
        null, null,
        "https://support.lenovo.com/",
        "Lenovo tools proprietary; link-out uses nothing.",
        "Link-out only in v1.");

    public static readonly OemVendor Intel = new(
        "intel", "Intel", OemCapability.LinkOutOnly,
        "Component vendor (device provider); DSA has no verified scriptable CLI in v1",
        null, null,
        "https://www.intel.com/content/www/us/en/support/detect.html",
        "Intel DSA proprietary; link-out uses nothing.",
        "Link-out only in v1.");

    public static readonly OemVendor Nvidia = new(
        "nvidia", "NVIDIA", OemCapability.LinkOutOnly,
        "Component vendor (device provider); GeForce Experience has no verified scriptable CLI in v1",
        null, null,
        "https://www.geforce.com/drivers",
        "NVIDIA proprietary; link-out uses nothing.",
        "Link-out only in v1.");

    public static readonly OemVendor Amd = new(
        "amd", "AMD", OemCapability.LinkOutOnly,
        "Component vendor (device provider); Adrenalin has no verified scriptable CLI in v1",
        null, null,
        "https://www.amd.com/en/support",
        "AMD proprietary; link-out uses nothing.",
        "Link-out only in v1.");

    public static readonly OemVendor Hp = new(
        "hp", "HP", OemCapability.LinkOutOnly,
        "Manufacturer contains 'HP'/'Hewlett'; Support Assistant has no verified scriptable CLI in v1",
        null, null,
        "https://support.hp.com/drivers",
        "HP proprietary; link-out uses nothing.",
        "Link-out only in v1.");

    public static IReadOnlyList<OemVendor> All { get; } =
    [
        Dell, Lenovo, Intel, Nvidia, Amd, Hp,
    ];

    public static OemVendor? Find(string id) =>
        All.FirstOrDefault(v => string.Equals(v.Id, id, StringComparison.OrdinalIgnoreCase));

    // Machine-vendor match from a WMI manufacturer string. Fuzzy on
    // purpose (vendors spell themselves many ways); unknown answers
    // null and the ladder falls back to Windows Update + generic
    // guidance — never a guessed vendor.
    public static OemVendor? MatchManufacturer(string? manufacturer)
    {
        if (string.IsNullOrWhiteSpace(manufacturer))
        {
            return null;
        }

        string m = manufacturer.ToUpperInvariant();
        if (m.Contains("DELL"))
        {
            return Dell;
        }

        if (m.Contains("LENOVO"))
        {
            return Lenovo;
        }

        // "HP" must be a real token — a raw substring would match
        // unrelated names. Known forms: HP, HP Inc., HPE, Hewlett-*.
        bool hp = m.Split([' ', '-', ','], StringSplitOptions.RemoveEmptyEntries)
            .Any(t => t is "HP" or "HPE" || t.StartsWith("HEWLETT"));
        if (hp)
        {
            return Hp;
        }

        return null;
    }

    // Component-vendor match from a device provider string (pnputil /
    // WMI provider names). Same honesty rule: unknown is null.
    public static OemVendor? MatchProvider(string? provider)
    {
        if (string.IsNullOrWhiteSpace(provider))
        {
            return null;
        }

        string p = provider.ToUpperInvariant();
        if (p.Contains("INTEL"))
        {
            return Intel;
        }

        if (p.Contains("NVIDIA") || p.Contains("NVIDA"))
        {
            return Nvidia;
        }

        if (p.Contains("AMD") || p.Contains("ADVANCED MICRO"))
        {
            return Amd;
        }

        if (p.Contains("DELL"))
        {
            return Dell;
        }

        if (p.Contains("LENOVO"))
        {
            return Lenovo;
        }

        if (p.Contains("HEWLETT") || p == "HP" || p.StartsWith("HP "))
        {
            return Hp;
        }

        return null;
    }
}
