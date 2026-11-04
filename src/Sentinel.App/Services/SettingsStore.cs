using System.IO;
using System.Text.Json;

namespace Sentinel.App.Services;

// R4-working-subset settings (02 §16): every stored value backs a
// control that works TODAY (E30's L-permissions back the action
// dispatcher; their full Settings UI arrives with N62). Lines whose
// backends don't exist yet (scheduler, photo egress, vault periods,
// language) return with their backends — they are ABSENT here, not
// dead. JSON file, atomic replace, corrupt file -> defaults.
public sealed record SentinelSettings(
    string DefaultScanMode,
    int BalancedCapPercent,
    bool AiEnabled,
    IReadOnlyList<string> NeverTouch,
    string Theme,
    double FontScale,
    // A10 (05 §6): pre-A10 settings files lack this key, and the
    // default parameter value is what keeps them on the protected
    // default instead of silently flipping to false.
    bool PauseOnLowBattery = true,
    // P21 (02 §16A): priority watch defaults ON while the app is
    // open (03 §4). Same legacy-compat pattern as above.
    bool PriorityWatchEnabled = true,
    // U20 (02 §16E): Reduce Motion + High Contrast, both default
    // off (current rendering). Legacy files lack both keys.
    bool ReduceMotion = false,
    bool HighContrast = false,
    // E30 (05 §3): per-module L0–L3 permission levels. Default L2
    // (Fix with approval). Drivers/Threats are capped at L2 by the
    // provider, not by storage; System covers restore points,
    // report export, and knowledge packs.
    int CleanerPermission = 2,
    int DriversPermission = 2,
    int ThreatsPermission = 2,
    int StartupPermission = 2,
    int PerformancePermission = 2,
    int SystemPermission = 2,
    // E36 (05 §3.1): L3 unattended auto-clean. Default OFF —
    // owner-configured, never assumed. Even when on, only the
    // envelope (SAFE + 24h + Vault-only + caps) may run.
    bool L3AutoCleanEnabled = false,
    // E37 (R35): vault retention REVIEW period in days. A review
    // flag only — nothing is ever auto-deleted on expiry.
    int VaultReviewDays = 30)
{
    public static SentinelSettings Defaults { get; } = new(
        "Balanced", 25, true, [], "Dark", 1.0, true, true, false, false,
        2, 2, 2, 2, 2, 2, false, 30);

    public SentinelSettings Sanitized()
    {
        string mode = DefaultScanMode is "Eco" or "Balanced" ? DefaultScanMode : "Balanced";
        int cap = Math.Clamp(BalancedCapPercent, 10, 30);
        string theme = Theme is "Light" or "Dark" or "System" ? Theme : "Dark";
        double font = Math.Clamp(FontScale, 0.9, 1.25);
        var never = (NeverTouch ?? []).Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => p.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(200)
            .ToList();
        int reviewDays = VaultReviewDays is 7 or 30 or 90 ? VaultReviewDays : 30;
        return new SentinelSettings(mode, cap, AiEnabled, never, theme, font, PauseOnLowBattery, PriorityWatchEnabled, ReduceMotion, HighContrast,
            Math.Clamp(CleanerPermission, 0, 3), Math.Clamp(DriversPermission, 0, 3),
            Math.Clamp(ThreatsPermission, 0, 3), Math.Clamp(StartupPermission, 0, 3),
            Math.Clamp(PerformancePermission, 0, 3), Math.Clamp(SystemPermission, 0, 3),
            L3AutoCleanEnabled, reviewDays);
    }
}

public sealed class SettingsStore
{
    private readonly string _path;

    public SettingsStore(string path)
    {
        _path = path;
    }

    public SentinelSettings Load()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return SentinelSettings.Defaults;
            }

            var loaded = JsonSerializer.Deserialize<SentinelSettings>(
                File.ReadAllText(_path),
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            return (loaded ?? SentinelSettings.Defaults).Sanitized();
        }
        catch
        {
            return SentinelSettings.Defaults;
        }
    }

    public void Save(SentinelSettings settings)
    {
        var clean = settings.Sanitized();
        string? dir = Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        string temp = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(clean, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(temp, _path, overwrite: true);
    }
}
