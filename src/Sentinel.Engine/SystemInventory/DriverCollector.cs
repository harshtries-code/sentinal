using System.Management;
using System.Runtime.InteropServices;

namespace Sentinel.Engine.SystemInventory;

// READ-ONLY: device/driver inventory via WMI. No device is touched.
public static class DriverCollector
{
    private const string Scope = "Win32_PnPSignedDriver (device, version, date, signer, status, hardware ID)";

    public static CollectionResult<DriverRecord> Collect()
    {
        var observed = DateTime.UtcNow;
        var result = new List<DriverRecord>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT DeviceName, DriverVersion, DriverDate, Signer, Status, HardwareID " +
                "FROM Win32_PnPSignedDriver");
            foreach (var obj in searcher.Get())
            {
                using (obj)
                {
                    result.Add(new DriverRecord(
                        DeviceName: ToStr(obj, "DeviceName") ?? "(unknown device)",
                        DriverVersion: ToStr(obj, "DriverVersion"),
                        DriverDate: ToStr(obj, "DriverDate"),
                        Signer: ToStr(obj, "Signer"),
                        Status: ToStr(obj, "Status"),
                        HardwareId: ParseHardwareId(SafeGet(obj, "HardwareID"))));
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or COMException)
        {
            return CollectionResult<DriverRecord>.Fail(Scope, "WmiQueryFailed", ex.GetType().Name);
        }

        return CollectionResult<DriverRecord>.Ok(result, Scope);
    }

    // Device Manager health view: devices whose problem code is set.
    // Source is SetupAPI (live, same as Device Manager) because the
    // WMI snapshot misses disconnected/phantom problems (M3 VM ground
    // truth: code-45 monitor + CD-ROM invisible to Win32_PnPEntity).
    // Names come from SetupAPI registry properties (works for phantoms
    // too); WMI is a name fallback only. SetupAPI unusable → WMI
    // fallback with an honest gap.
    public static CollectionResult<DeviceProblemRecord> CollectDeviceProblems()
    {
        const string scope = "SetupAPI device status (Device Manager source)";
        var observed = DateTime.UtcNow;
        var rows = DeviceSetupApi.TryEnumerate(out string? fault);
        if (rows is null)
        {
            return CollectDeviceProblemsWmi($"SetupAPI unusable ({fault})");
        }

        var names = ReadWmiDisplayNames();
        var result = rows
            .Where(r => r.Problem != 0)
            .Select(r => new DeviceProblemRecord(
                DeviceId: r.Id,
                Name: r.Name ?? (names.TryGetValue(r.Id, out var n) ? n : "(unknown device)"),
                ErrorCode: (int)r.Problem,
                ErrorName: ProblemName((int)r.Problem),
                Status: "flags=0x" + r.Status.ToString("X")))
            .OrderBy(r => r.DeviceId, StringComparer.OrdinalIgnoreCase)
            .ToList();
        return CollectionResult<DeviceProblemRecord>.Ok(result, scope);
    }

    private static Dictionary<string, string> ReadWmiDisplayNames()
    {
        var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT DeviceID, Name FROM Win32_PnPEntity");
            foreach (var obj in searcher.Get())
            {
                using (obj)
                {
                    string? id = ToStr(obj, "DeviceID");
                    string? name = ToStr(obj, "Name");
                    if (!string.IsNullOrEmpty(id) && !string.IsNullOrEmpty(name))
                    {
                        names.TryAdd(id, name);
                    }
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or COMException)
        {
            // Names are best-effort; problems stand without them.
        }

        return names;
    }

    private static CollectionResult<DeviceProblemRecord> CollectDeviceProblemsWmi(string reason)
    {
        string scope = "Win32_PnPEntity fallback (" + reason + ")";
        var observed = DateTime.UtcNow;
        var result = new List<DeviceProblemRecord>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT DeviceID, Name, ConfigManagerErrorCode, Status FROM Win32_PnPEntity");
            foreach (var obj in searcher.Get())
            {
                using (obj)
                {
                    int? code = ToInt(obj, "ConfigManagerErrorCode");
                    if (code is null || code.Value == 0)
                    {
                        continue;
                    }

                    result.Add(new DeviceProblemRecord(
                        DeviceId: ToStr(obj, "DeviceID") ?? "(unknown id)",
                        Name: ToStr(obj, "Name") ?? "(unknown device)",
                        ErrorCode: code.Value,
                        ErrorName: ProblemName(code.Value),
                        Status: ToStr(obj, "Status")));
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or COMException)
        {
            return CollectionResult<DeviceProblemRecord>.Fail(scope, "WmiQueryFailed", ex.GetType().Name);
        }

        return new CollectionResult<DeviceProblemRecord>(
            CollectionStatus.Partial, result, scope, observed,
            [new CollectionGap(scope, "WmiFallback", "phantom problems may be missed")],
            false);
    }

    private static string ProblemName(int code)
    {
        return code switch
        {
            1 => "Not configured correctly",
            10 => "Cannot start",
            12 => "No free resources",
            14 => "Requires restart",
            18 => "Reinstall drivers",
            19 => "Registry configuration damaged",
            22 => "Disabled",
            24 => "Not present or not working",
            28 => "Drivers not installed",
            31 => "Cannot load required drivers",
            32 => "Driver service disabled",
            39 => "Driver corrupt or missing",
            41 => "Driver loaded, device not found",
            43 => "Reported problems (stopped)",
            45 => "Currently disconnected",
            48 => "Software blocked the device",
            52 => "Cannot verify digital signature",
            _ => $"Code {code}",
        };
    }

    private static int? ToInt(ManagementBaseObject obj, string name)
    {
        try
        {
            var value = obj[name];
            return value is null ? null : Convert.ToInt32(value);
        }
        catch
        {
            return null;
        }
    }

    // Win32_PnPSignedDriver.HardwareID is documented as a string and is
    // null for devices without one. Other shapes are preserved
    // best-effort, never silently dropped to null when data exists.
    public static string? ParseHardwareId(object? value)
    {
        return value switch
        {
            null => null,
            string s => string.IsNullOrWhiteSpace(s) ? null : s.Trim(),
            string[] ids => ids.FirstOrDefault(i => !string.IsNullOrWhiteSpace(i))?.Trim(),
            Array a => a.Cast<object?>().FirstOrDefault(o => o is not null)?.ToString(),
            _ => value.ToString(),
        };
    }

    private static object? SafeGet(ManagementBaseObject obj, string name)
    {
        try
        {
            return obj[name];
        }
        catch
        {
            return null;
        }
    }

    private static string? ToStr(ManagementBaseObject obj, string name)
    {
        var value = SafeGet(obj, name)?.ToString();
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }
}
