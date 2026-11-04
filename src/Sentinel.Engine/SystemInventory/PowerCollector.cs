using System.Management;
using System.Runtime.InteropServices;

namespace Sentinel.Engine.SystemInventory;

// READ-ONLY: battery + disk health via WMI. Reports only what the
// hardware exposes; missing values stay null (honest-note rule).
public static class PowerCollector
{
    public static CollectionResult<BatteryRecord> CollectBatteries()
    {
        const string scope = "Win32_Battery + ROOT\\WMI capacity/cycle classes";
        var observed = DateTime.UtcNow;
        var result = new List<BatteryRecord>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, EstimatedChargeRemaining, BatteryStatus FROM Win32_Battery");
            foreach (var obj in searcher.Get())
            {
                using (obj)
                {
                    result.Add(new BatteryRecord(
                        Name: ToStr(obj, "Name") ?? "(battery)",
                        ChargePercent: ToInt(obj, "EstimatedChargeRemaining"),
                        Status: BatteryStatusName(ToInt(obj, "BatteryStatus")),
                        FullChargedCapacityMWh: QuerySingleLong(
                            @"ROOT\WMI",
                            "SELECT FullChargedCapacity FROM BatteryFullChargedCapacity",
                            "FullChargedCapacity"),
                        DesignCapacityMWh: QuerySingleLong(
                            @"ROOT\WMI",
                            "SELECT DesignedCapacity FROM BatteryStaticData",
                            "DesignedCapacity"),
                        CycleCount: QuerySingleInt(
                            @"ROOT\WMI",
                            "SELECT CycleCount FROM BatteryCycleCount",
                            "CycleCount")));
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or COMException)
        {
            return CollectionResult<BatteryRecord>.Fail(scope, "BatteryQueryFailed", ex.GetType().Name);
        }

        // Empty success here means no battery device exists (desktop),
        // which is a real observation, not a failure.
        return CollectionResult<BatteryRecord>.Ok(result, scope);
    }

    public static CollectionResult<DiskHealthRecord> CollectDisks()
    {
        const string scope = "MSFT_PhysicalDisk (storage namespace)";
        var observed = DateTime.UtcNow;
        var result = new List<DiskHealthRecord>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"ROOT\Microsoft\Windows\Storage",
                "SELECT FriendlyName, MediaType, HealthStatus, OperationalStatus FROM MSFT_PhysicalDisk");
            foreach (var obj in searcher.Get())
            {
                using (obj)
                {
                    result.Add(new DiskHealthRecord(
                        Name: ToStr(obj, "FriendlyName") ?? "(disk)",
                        MediaType: MediaTypeName(ToInt(obj, "MediaType")),
                        HealthStatus: HealthName(ToInt(obj, "HealthStatus")),
                        OperationalStatus: string.Join(",", OperationalNames(obj))));
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or COMException)
        {
            return CollectionResult<DiskHealthRecord>.Fail(scope, "StorageQueryFailed", ex.GetType().Name);
        }

        return CollectionResult<DiskHealthRecord>.Ok(result, scope);
    }

    private static string? ToStr(ManagementBaseObject obj, string name)
    {
        try
        {
            var value = obj[name]?.ToString();
            return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
        }
        catch
        {
            return null;
        }
    }

    private static int? ToInt(ManagementBaseObject obj, string name)
    {
        try
        {
            var value = obj[name];
            if (value is null)
            {
                return null;
            }

            return Convert.ToInt32(value);
        }
        catch
        {
            return null;
        }
    }

    private static long? QuerySingleLong(string scope, string query, string property)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(scope, query);
            foreach (var obj in searcher.Get())
            {
                using (obj)
                {
                    var value = obj[property];
                    if (value is not null)
                    {
                        return Convert.ToInt64(value);
                    }
                }
            }
        }
        catch
        {
            // Class absent on this machine: null is honest.
        }

        return null;
    }

    private static int? QuerySingleInt(string scope, string query, string property)
    {
        var value = QuerySingleLong(scope, query, property);
        return value is null ? null : (int)Math.Min(value.Value, int.MaxValue);
    }

    private static string? BatteryStatusName(int? code)
    {
        return code switch
        {
            1 => "Discharging",
            2 => "On AC",
            3 => "Fully charged",
            4 => "Low",
            5 => "Critical",
            6 => "Charging",
            _ => null,
        };
    }

    private static string MediaTypeName(int? code)
    {
        return code switch
        {
            3 => "HDD",
            4 => "SSD",
            5 => "SCM",
            _ => "Unknown",
        };
    }

    private static string HealthName(int? code)
    {
        return code switch
        {
            0 => "Healthy",
            1 => "Warning",
            2 => "Unhealthy",
            _ => "Unknown",
        };
    }

    private static IEnumerable<string> OperationalNames(ManagementBaseObject obj)
    {
        ushort[]? codes = null;
        try
        {
            codes = obj["OperationalStatus"] as ushort[];
        }
        catch
        {
            yield break;
        }

        if (codes is null || codes.Length == 0)
        {
            yield return "Unknown";
            yield break;
        }

        foreach (var code in codes)
        {
            yield return code switch
            {
                0 => "Unknown",
                1 => "Other",
                2 => "OK",
                3 => "Degraded",
                5 => "Predictive failure",
                6 => "Error",
                _ => $"Code {code}",
            };
        }
    }
}
