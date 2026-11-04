using System.Diagnostics.Eventing.Reader;

namespace Sentinel.Engine.SystemInventory;

// READ-ONLY: recent errors/warnings from System + Application logs.
// Messages are truncated at collection time; nothing is written back.
// A log that cannot be read is reported as a gap, never as clean.
public static class EventCollector
{
    private const int MessageCap = 2000;

    // Valid Windows Event Log XPath: predicate directly on System.
    // (The earlier `System/[(...)]` form was rejected by the API.)
    internal const string QueryText = "*[System[(Level=1 or Level=2 or Level=3)]]";

    public static CollectionResult<EventRecord> CollectRecent(int perLog = 100)
    {
        const string scope = "System+Application (Critical/Error/Warning, newest first)";
        var observed = DateTime.UtcNow;
        var records = new List<EventRecord>();
        var gaps = new List<CollectionGap>();
        bool truncated = false;
        int logsOk = 0;

        foreach (var log in new[] { "System", "Application" })
        {
            var (rows, gap, hitCap) = CollectLog(log, perLog);
            records.AddRange(rows);
            truncated |= hitCap;
            if (gap is null)
            {
                logsOk++;
            }
            else
            {
                gaps.Add(gap);
            }
        }

        var status = logsOk == 2 ? CollectionStatus.Success
            : logsOk == 1 ? CollectionStatus.Partial
            : CollectionStatus.Failed;
        return new CollectionResult<EventRecord>(status, records, scope, observed, gaps, truncated);
    }

    // Targeted read: channel + provider + level + time filters with
    // durable record IDs and bounded structured properties, for
    // correlation (device/disk/crash stories) and the query_events
    // tool. Newest first.
    public static CollectionResult<TargetedEventRecord> CollectTargeted(
        string log,
        string? provider,
        int maxLevel,
        DateTime sinceUtc,
        int maxRows)
    {
        string scope = $"{log} (Level<={maxLevel}, provider {(provider ?? "any")})";
        var observed = DateTime.UtcNow;
        if (provider is not null && provider.Contains('\''))
        {
            return CollectionResult<TargetedEventRecord>.Fail(
                scope, "BadProvider", "quote rejected");
        }

        var predicates = new List<string>
        {
            "(Level>=1 and Level<=" + Math.Clamp(maxLevel, 1, 4) + ")",
            "TimeCreated[@SystemTime>='" + sinceUtc.ToUniversalTime().ToString("O") + "']",
        };
        if (!string.IsNullOrWhiteSpace(provider))
        {
            predicates.Add("Provider[@Name='" + provider + "']");
        }

        string query = "*[System[" + string.Join(" and ", predicates) + "]]";
        var (rows, gap, hitCap) = ReadTargeted(log, query, Math.Max(1, maxRows));
        if (gap is not null && rows.Count == 0)
        {
            return new CollectionResult<TargetedEventRecord>(
                CollectionStatus.Failed, rows, scope, observed, [gap], false);
        }

        return new CollectionResult<TargetedEventRecord>(
            gap is null ? CollectionStatus.Success : CollectionStatus.Partial,
            rows, scope, observed,
            gap is null ? Array.Empty<CollectionGap>() : [gap], hitCap);
    }

    // Boot/filesystem check history: Chkdsk + Wininit reports in the
    // Application log, ALL levels (informational included). Inspecting
    // these reports never repairs anything.
    public static CollectionResult<TargetedEventRecord> CollectChkdskHistory(
        DateTime sinceUtc, int maxRows = 50)
    {
        const string scope = "Application (Chkdsk + Wininit reports, all levels)";
        var observed = DateTime.UtcNow;
        string query = "*[System[Provider[@Name='Chkdsk' or @Name='Wininit']"
            + " and TimeCreated[@SystemTime>='" + sinceUtc.ToUniversalTime().ToString("O") + "']]]";
        var (rows, gap, hitCap) = ReadTargeted("Application", query, Math.Max(1, maxRows));
        if (gap is not null && rows.Count == 0)
        {
            return new CollectionResult<TargetedEventRecord>(
                CollectionStatus.Failed, rows, scope, observed, [gap], false);
        }

        return new CollectionResult<TargetedEventRecord>(
            gap is null ? CollectionStatus.Success : CollectionStatus.Partial,
            rows, scope, observed,
            gap is null ? Array.Empty<CollectionGap>() : [gap], hitCap);
    }

    private static (List<TargetedEventRecord> Rows, CollectionGap? Gap, bool HitCap) ReadTargeted(
        string log, string query, int max)
    {
        var rows = new List<TargetedEventRecord>();
        EventLogReader? reader = null;
        try
        {
            var eventsQuery = new EventLogQuery(log, PathType.LogName, query)
            {
                ReverseDirection = true,
            };
            reader = new EventLogReader(eventsQuery);
            while (rows.Count < max)
            {
                try
                {
                    using var evt = reader.ReadEvent();
                    if (evt is null)
                    {
                        break;
                    }

                    var props = new List<string>();
                    try
                    {
                        foreach (var prop in evt.Properties)
                        {
                            if (props.Count >= 8)
                            {
                                break;
                            }

                            string value = prop.Value?.ToString() ?? string.Empty;
                            props.Add(value.Length > 200 ? value.Substring(0, 200) + "…" : value);
                        }
                    }
                    catch
                    {
                        // Structured properties are best-effort.
                    }

                    // Events without a message template (custom IDs under
                    // a foreign source) render no description: fall back
                    // to the structured properties so the payload is
                    // still retrievable (M3 VM ground truth).
                    string message = evt.FormatDescription() ?? string.Empty;
                    if (string.IsNullOrWhiteSpace(message) && props.Count > 0)
                    {
                        message = "properties: " + string.Join("; ", props);
                    }

                    rows.Add(new TargetedEventRecord(
                        log,
                        evt.RecordId ?? 0,
                        evt.Id,
                        LevelName(evt.Level),
                        evt.TimeCreated?.ToUniversalTime() ?? DateTime.MinValue,
                        evt.ProviderName ?? string.Empty,
                        Truncate(message),
                        props));
                }
                catch (Exception ex)
                {
                    return (rows, new CollectionGap(log, "ReadError", ex.GetType().Name), rows.Count >= max);
                }
            }

            return (rows, null, rows.Count >= max);
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or InvalidOperationException)
        {
            return (rows, new CollectionGap(log, "LogUnreadable", ex.GetType().Name), false);
        }
        finally
        {
            reader?.Dispose();
        }
    }

    private static (List<EventRecord> Rows, CollectionGap? Gap, bool HitCap) CollectLog(string log, int max)
    {
        var rows = new List<EventRecord>();
        EventLogQuery? eventsQuery = null;
        EventLogReader? reader = null;
        try
        {
            eventsQuery = new EventLogQuery(log, PathType.LogName, QueryText)
            {
                ReverseDirection = true,
            };
            reader = new EventLogReader(eventsQuery);
            int taken = 0;
            while (taken < max)
            {
                EventRecordData? data;
                try
                {
                    using var evt = reader.ReadEvent();
                    if (evt is null)
                    {
                        break;
                    }

                    data = new EventRecordData(
                        evt.Id,
                        LevelName(evt.Level),
                        evt.TimeCreated?.ToUniversalTime() ?? DateTime.MinValue,
                        evt.ProviderName ?? string.Empty,
                        Truncate(evt.FormatDescription() ?? string.Empty));
                }
                catch (Exception ex)
                {
                    return (rows, new CollectionGap(log, "ReadError", ex.GetType().Name), taken >= max);
                }

                rows.Add(new EventRecord(log, data.Id, data.Level, data.TimeUtc, data.Provider, data.Message));
                taken++;
            }

            return (rows, null, taken >= max);
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or InvalidOperationException)
        {
            return (rows, new CollectionGap(log, "LogUnreadable", ex.GetType().Name), false);
        }
        finally
        {
            reader?.Dispose();
        }
    }

    private static string LevelName(byte? level)
    {
        return level switch
        {
            1 => "Critical",
            2 => "Error",
            3 => "Warning",
            _ => "Info",
        };
    }

    private static string Truncate(string message)
    {
        if (message.Length <= MessageCap)
        {
            return message;
        }

        return message.Substring(0, MessageCap) + "…[truncated]";
    }

    private sealed record EventRecordData(int Id, string Level, DateTime TimeUtc, string Provider, string Message);
}
