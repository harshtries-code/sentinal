using System.Management;
using System.Runtime.InteropServices;

namespace Sentinel.Engine.SystemInventory;

// READ-ONLY Defender observation (M4): protection state + threat
// detections from the Defender WMI provider. No scans are started,
// nothing is remediated, quarantined, restored, or excluded —
// orchestration lives in Phase 5 templates (05 §4), observation
// lives here. A healthy machine yields ZERO detection rows with
// Success status: "none observed", stated, not inferred.
public static class DefenderCollector
{
    private const string ScopeStatus = "Defender status (MSFT_MpComputerStatus, read-only WMI)";
    private const string ScopeDetections = "Defender detections (MSFT_MpThreat + MSFT_MpThreatDetection, read-only WMI)";
    private const string Namespace = @"root\Microsoft\Windows\Defender";

    public static CollectionResult<DefenderStatusRecord> CollectStatus()
    {
        var observed = DateTime.UtcNow;
        try
        {
            using var searcher = new ManagementObjectSearcher(
                Namespace, "SELECT * FROM MSFT_MpComputerStatus");
            using var results = searcher.Get();
            foreach (ManagementObject obj in results)
            {
                using (obj)
                {
                    var record = new DefenderStatusRecord(
                        AntivirusEnabled: ToBool(obj, "AntivirusEnabled"),
                        RealTimeProtectionEnabled: ToBool(obj, "RealTimeProtectionEnabled"),
                        BehaviorMonitorEnabled: ToBool(obj, "BehaviorMonitorEnabled"),
                        TamperProtectionSource: ToStr(obj, "TamperProtectionSource"),
                        EngineVersion: ToStr(obj, "AMEngineVersion"),
                        SignatureVersion: ToStr(obj, "AntivirusSignatureVersion"),
                        SignatureLastUpdatedUtc: ToUtc(obj, "AntivirusSignatureLastUpdated"),
                        SignatureAgeDays: ToInt(obj, "AntivirusSignatureAge"),
                        LastQuickScanUtc: ToUtc(obj, "QuickScanEndTime") ?? ToUtc(obj, "QuickScanStartTime"),
                        LastFullScanUtc: ToUtc(obj, "FullScanEndTime") ?? ToUtc(obj, "FullScanStartTime"),
                        QuickScanAgeDays: ToInt(obj, "QuickScanAge"),
                        FullScanAgeDays: ToInt(obj, "FullScanAge"));
                    return new CollectionResult<DefenderStatusRecord>(
                        CollectionStatus.Success, [record], ScopeStatus, observed,
                        Array.Empty<CollectionGap>(), false);
                }
            }

            return CollectionResult<DefenderStatusRecord>.Fail(
                ScopeStatus, "NoInstance", "MSFT_MpComputerStatus returned zero rows.");
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or COMException)
        {
            // Namespace missing (no Defender platform / third-party AV
            // owns protection) or denied: could not observe, stated.
            return CollectionResult<DefenderStatusRecord>.Fail(ScopeStatus, "WmiQueryFailed", ex.GetType().Name);
        }
    }

    public static CollectionResult<DefenderDetectionRecord> CollectDetections(int limit = 50)
    {
        var observed = DateTime.UtcNow;
        if (limit < 1)
        {
            limit = 1;
        }

        try
        {
            var threats = new Dictionary<long, (string Name, int Severity, int Category, bool Active)>();
            using (var searcher = new ManagementObjectSearcher(
                Namespace, "SELECT ThreatID, ThreatName, SeverityID, CategoryID, IsActive FROM MSFT_MpThreat"))
            using (var results = searcher.Get())
            {
                foreach (ManagementObject obj in results)
                {
                    using (obj)
                    {
                        long id = ToLong(obj, "ThreatID");
                        threats[id] = (
                            ToStr(obj, "ThreatName") ?? $"(threat {id})",
                            ToInt(obj, "SeverityID") ?? 0,
                            ToInt(obj, "CategoryID") ?? 0,
                            ToBool(obj, "IsActive") ?? false);
                    }
                }
            }

            var records = new List<DefenderDetectionRecord>();
            bool truncated = false;
            using (var searcher = new ManagementObjectSearcher(
                Namespace, "SELECT ThreatID, DetectionID, Resources, ProcessName, InitialDetectionTime, RemediationTime, CleaningActionID FROM MSFT_MpThreatDetection"))
            using (var results = searcher.Get())
            {
                foreach (ManagementObject obj in results)
                {
                    using (obj)
                    {
                        if (records.Count >= limit)
                        {
                            truncated = true;
                            break;
                        }

                        long id = ToLong(obj, "ThreatID");
                        threats.TryGetValue(id, out var threat);
                        DateTime? remediated = ToUtc(obj, "RemediationTime");
                        records.Add(new DefenderDetectionRecord(
                            ThreatName: threat.Name ?? $"(threat {id})",
                            ThreatId: (int)Math.Clamp(id, int.MinValue, int.MaxValue),
                            Severity: SeverityName(threat.Severity),
                            Category: CategoryName(threat.Category),
                            Path: FirstResource(ToStr(obj, "Resources")) ?? ToStr(obj, "ProcessName"),
                            DetectedUtc: ToUtc(obj, "InitialDetectionTime"),
                            ActionTaken: remediated is null ? null : CleaningActionName(ToInt(obj, "CleaningActionID") ?? 0),
                            PendingAction: remediated is null && threat.Active));
                    }
                }
            }

            records.Sort((a, b) => Nullable.Compare(b.DetectedUtc, a.DetectedUtc));
            return new CollectionResult<DefenderDetectionRecord>(
                CollectionStatus.Success, records, ScopeDetections, observed,
                Array.Empty<CollectionGap>(), truncated);
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or COMException)
        {
            return CollectionResult<DefenderDetectionRecord>.Fail(ScopeDetections, "WmiQueryFailed", ex.GetType().Name);
        }
    }

    private static string SeverityName(int id) => id switch
    {
        1 => "Low",
        2 => "Moderate",
        4 => "High",
        5 => "Severe",
        _ => $"Unknown({id})",
    };

    private static string CategoryName(int id) => id switch
    {
        1 => "Adware",
        2 => "Spyware",
        3 => "Password stealer",
        4 => "Trojan downloader",
        5 => "Worm",
        6 => "Backdoor",
        7 => "Remote access trojan",
        8 => "Trojan",
        10 => "Keylogger",
        13 => "Browser modifier",
        19 => "Joke program",
        21 => "Software bundler",
        23 => "Settings modifier",
        27 => "Potentially unwanted software",
        33 => "Behavior",
        34 => "Vulnerability",
        36 => "Ransomware",
        _ => $"Category({id})",
    };

    private static string CleaningActionName(int id) => id switch
    {
        1 => "Clean",
        2 => "Quarantine",
        3 => "Remove",
        6 => "Allow",
        8 => "Block",
        9 => "Quarantine (user)",
        _ => $"Action({id})",
    };

    private static string? FirstResource(string? resources)
    {
        if (string.IsNullOrWhiteSpace(resources))
        {
            return null;
        }

        // "file:_C:\path|webfile:http://..." — first item, prefix cut.
        int bar = resources.IndexOf('|');
        string first = (bar < 0 ? resources : resources[..bar]).Trim();
        int colon = first.IndexOf(':');
        string path = colon < 0 ? first : first[(colon + 1)..].TrimStart('_').Trim();
        return path.Length == 0 ? null : path.Length > 260 ? path[..260] : path;
    }

    private static bool? ToBool(ManagementObject obj, string name)
    {
        try
        {
            var value = obj[name];
            return value is null ? null : Convert.ToBoolean(value);
        }
        catch
        {
            return null;
        }
    }

    private static int? ToInt(ManagementObject obj, string name)
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

    private static long ToLong(ManagementObject obj, string name)
    {
        try
        {
            var value = obj[name];
            return value is null ? 0 : Convert.ToInt64(value);
        }
        catch
        {
            return 0;
        }
    }

    private static string? ToStr(ManagementObject obj, string name)
    {
        try
        {
            return FlattenWmiValue(obj[name]);
        }
        catch
        {
            return null;
        }
    }

    // WMI array properties (e.g. MSFT_MpThreatDetection.Resources) stringify
    // to "System.String[]" under Convert.ToString. Flatten to the first
    // non-empty element so display strings stay readable.
    internal static string? FlattenWmiValue(object? value)
    {
        if (value is Array items)
        {
            foreach (var item in items)
            {
                string? element = Convert.ToString(item);
                if (!string.IsNullOrWhiteSpace(element))
                {
                    return element.Trim();
                }
            }

            return null;
        }

        string text = Convert.ToString(value) ?? string.Empty;
        return string.IsNullOrWhiteSpace(text) ? null : text.Trim();
    }

    private static DateTime? ToUtc(ManagementObject obj, string name)
    {
        try
        {
            var value = obj[name];
            if (value is null)
            {
                return null;
            }

            return ManagementDateTimeConverter.ToDateTime(Convert.ToString(value)).ToUniversalTime();
        }
        catch
        {
            return null;
        }
    }
}
