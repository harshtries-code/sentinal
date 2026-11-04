using System.Management;
using System.Runtime.InteropServices;

namespace Sentinel.Engine.SystemInventory;

// READ-ONLY: Windows Reliability Monitor data (the same store behind
// perfmon /rel). Records are failureSTD/ informational rows RAC kept;
// the stability index is the published 1–10 daily score. Nothing is
// written back; an unreadable store is a gap, never a clean bill.
public sealed record ReliabilityRecord(
    DateTime TimeUtc,
    int EventId,
    string Source,
    string? Product,
    string Message);

public sealed record ReliabilityMetric(
    DateTime DayUtc,
    double? StabilityIndex);

public static class ReliabilityCollector
{
    private const int MessageCap = 500;

    public static CollectionResult<ReliabilityRecord> CollectRecords(
        DateTime sinceUtc, int maxRows = 200)
    {
        const string scope = "Win32_ReliabilityRecords (newest first)";
        var observed = DateTime.UtcNow;
        var records = new List<ReliabilityRecord>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT TimeGenerated, EventIdentifier, SourceName, ProductName, Message " +
                "FROM Win32_ReliabilityRecords");
            // The RAC store is small (Windows curates it) and WMI
            // returns it unordered, so the cap applies AFTER sorting:
            // breaking mid-read could keep the oldest rows while
            // claiming newest-first.
            foreach (var obj in searcher.Get())
            {
                using (obj)
                {
                    DateTime? time = ToDate(obj, "TimeGenerated");
                    if (time is null || time.Value.ToUniversalTime() < sinceUtc.ToUniversalTime())
                    {
                        continue;
                    }

                    records.Add(new ReliabilityRecord(
                        time.Value.ToUniversalTime(),
                        ToInt(obj, "EventIdentifier") ?? 0,
                        ToStr(obj, "SourceName") ?? "(unknown source)",
                        ToStr(obj, "ProductName"),
                        Truncate(ToStr(obj, "Message") ?? string.Empty)));
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or COMException)
        {
            return CollectionResult<ReliabilityRecord>.Fail(
                scope, "WmiQueryFailed", ex.GetType().Name);
        }

        records.Sort((a, b) => b.TimeUtc.CompareTo(a.TimeUtc));
        int cap = Math.Max(1, maxRows);
        bool truncated = records.Count > cap;
        return new CollectionResult<ReliabilityRecord>(
            CollectionStatus.Success, records.Take(cap).ToList(), scope, observed,
            Array.Empty<CollectionGap>(), truncated);
    }

    public static CollectionResult<ReliabilityMetric> CollectStabilityIndex(int maxRows = 30)
    {
        const string scope = "Win32_ReliabilityStabilityMetrics (newest first)";
        var observed = DateTime.UtcNow;
        var records = new List<ReliabilityMetric>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT EndMeasurementDate, SystemStabilityIndex " +
                "FROM Win32_ReliabilityStabilityMetrics");
            // One row per measured day (small); cap after sorting
            // so newest-first is always true (see records above).
            foreach (var obj in searcher.Get())
            {
                using (obj)
                {
                    DateTime? day = ToDate(obj, "EndMeasurementDate");
                    if (day is null)
                    {
                        continue;
                    }

                    records.Add(new ReliabilityMetric(
                        day.Value.ToUniversalTime().Date,
                        ToDouble(obj, "SystemStabilityIndex")));
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or COMException)
        {
            return CollectionResult<ReliabilityMetric>.Fail(
                scope, "WmiQueryFailed", ex.GetType().Name);
        }

        records.Sort((a, b) => b.DayUtc.CompareTo(a.DayUtc));
        int cap = Math.Max(1, maxRows);
        bool truncated = records.Count > cap;
        return new CollectionResult<ReliabilityMetric>(
            CollectionStatus.Success, records.Take(cap).ToList(), scope, observed,
            Array.Empty<CollectionGap>(), truncated);
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
            return value is null ? null : Convert.ToInt32(value);
        }
        catch
        {
            return null;
        }
    }

    private static double? ToDouble(ManagementBaseObject obj, string name)
    {
        try
        {
            var value = obj[name];
            return value is null ? null : Convert.ToDouble(value);
        }
        catch
        {
            return null;
        }
    }

    private static DateTime? ToDate(ManagementBaseObject obj, string name)
    {
        try
        {
            var value = obj[name]?.ToString();
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            return ManagementDateTimeConverter.ToDateTime(value);
        }
        catch
        {
            return null;
        }
    }

    private static string Truncate(string message)
    {
        if (message.Length <= MessageCap)
        {
            return message;
        }

        return message.Substring(0, MessageCap) + "…[truncated]";
    }
}
