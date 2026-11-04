using System.Security;
using Microsoft.Win32;

namespace Sentinel.Engine.SystemInventory;

// READ-ONLY view of Task Manager's enable/disable state: the
// StartupApproved registry values. Parse rule (observed Windows
// behavior, conservative): a value whose first byte is 0x02 means
// enabled; any other PRESENT value means disabled; a missing value
// means UNKNOWN (null) — never inferred. A disabled entry is still
// listed by the Run/folder collectors; this only fills in State.
public static class StartupApproval
{
    public const string BasePath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";

    // Maps collector Location strings to their approval shelf.
    // RunOnce shares the Run shelf (a missing value reads unknown).
    public static (RegistryHive Hive, string SubKey)? ShelfFor(string location) =>
        location switch
        {
            "HKCU Run" => (RegistryHive.CurrentUser, "Run"),
            "HKCU RunOnce" => (RegistryHive.CurrentUser, "Run"),
            "HKLM Run" => (RegistryHive.LocalMachine, "Run"),
            "HKLM RunOnce" => (RegistryHive.LocalMachine, "Run"),
            "HKLM Run (32-bit)" => (RegistryHive.LocalMachine, "Run32"),
            "Startup folder (user)" => (RegistryHive.CurrentUser, "StartupFolder"),
            "Startup folder (all users)" => (RegistryHive.LocalMachine, "StartupFolder"),
            _ => null,
        };

    public static bool? ParseState(byte[]? raw)
    {
        if (raw is null || raw.Length == 0)
        {
            return null;
        }

        return raw[0] == 0x02;
    }

    // Live read: one value, read-only, exceptions allowed to the
    // caller (the collector turns them into gaps).
    public static byte[]? ReadLive(RegistryHive hive, string subKey, string valueName)
    {
        using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
        using var key = baseKey.OpenSubKey(BasePath + "\\" + subKey, writable: false);
        return key?.GetValue(valueName) as byte[];
    }
}

// One machine boot moment, measured without WMI or admin rights:
// the tick counter never lies about how long the box has been up.
public sealed record BootInfo(
    DateTime? BootUtc,
    TimeSpan Uptime,
    string? Gap);

public static class BootCollector
{
    public static BootInfo Collect(Func<long>? tickReader = null)
    {
        long ticks;
        try
        {
            ticks = tickReader?.Invoke() ?? Environment.TickCount64;
        }
        catch (Exception ex)
        {
            return new BootInfo(null, TimeSpan.Zero,
                $"Uptime counter unreadable ({ex.GetType().Name}).");
        }

        if (ticks < 0)
        {
            return new BootInfo(null, TimeSpan.Zero,
                "Uptime counter returned a negative value.");
        }

        var uptime = TimeSpan.FromMilliseconds(ticks);
        return new BootInfo(DateTime.UtcNow - uptime, uptime, null);
    }

    public static string RenderLine(BootInfo boot)
    {
        if (boot.Gap is not null || boot.BootUtc is null)
        {
            return "Last boot: unknown (" + (boot.Gap ?? "no reading") + ")";
        }

        string up = boot.Uptime.TotalDays >= 1
            ? $"{(int)boot.Uptime.TotalDays}d {boot.Uptime.Hours}h"
            : boot.Uptime.TotalHours >= 1
                ? $"{(int)boot.Uptime.TotalHours}h {boot.Uptime.Minutes}m"
                : $"{(int)boot.Uptime.TotalMinutes}m";
        return $"Last boot {boot.BootUtc.Value.ToLocalTime():g} · uptime {up}";
    }
}
