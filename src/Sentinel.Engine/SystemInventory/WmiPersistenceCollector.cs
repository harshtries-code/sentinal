using System.Management;
using System.Runtime.InteropServices;

namespace Sentinel.Engine.SystemInventory;

// READ-ONLY WMI event-subscription inventory (root\subscription):
// __EventFilter rows + __FilterToConsumerBinding rows. This is the
// classic fileless-persistence shelf — every row the UI shows
// carries a check-first note (T51 suspicion rule H-wmi-binding).
// Bounded (100 + 100); an unreadable namespace is a gap, and an
// empty namespace is "nothing there", stated as observed.
public static class WmiPersistenceCollector
{
    public const int MaxRows = 100;

    public sealed record WmiPersistence(
        IReadOnlyList<WmiFilterRecord> Filters,
        IReadOnlyList<WmiBindingRecord> Bindings);

    public static CollectionResult<WmiPersistence> Collect()
    {
        const string scope = "WMI event subscriptions (root\\subscription)";
        var observed = DateTime.UtcNow;
        if (Environment.OSVersion.Platform != PlatformID.Win32NT)
        {
            return CollectionResult<WmiPersistence>.Fail(scope, "WindowsOnly");
        }

        var filters = new List<WmiFilterRecord>();
        var bindings = new List<WmiBindingRecord>();
        var gaps = new List<CollectionGap>();
        bool truncated = false;

        try
        {
            var options = new ConnectionOptions
            {
                Impersonation = ImpersonationLevel.Impersonate,
                EnablePrivileges = false,
            };
            var namespacePath = new ManagementScope(@"\\.\root\subscription", options);
            namespacePath.Connect();

            truncated |= QueryFilters(namespacePath, filters, gaps);
            truncated |= QueryBindings(namespacePath, bindings, gaps);
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or COMException)
        {
            return new CollectionResult<WmiPersistence>(
                CollectionStatus.Failed, [],
                scope, observed,
                [new CollectionGap(scope, "NamespaceUnreadable", ex.GetType().Name)], false);
        }

        if (truncated)
        {
            gaps.Add(new CollectionGap(scope, "Truncated", $"kept first {MaxRows} per shelf"));
        }

        var status = gaps.Count == 0 ? CollectionStatus.Success : CollectionStatus.Partial;
        return new CollectionResult<WmiPersistence>(
            status, [new WmiPersistence(filters, bindings)],
            scope, observed, gaps, truncated);
    }

    private static bool QueryFilters(
        ManagementScope scope, List<WmiFilterRecord> filters, List<CollectionGap> gaps)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                scope, new ObjectQuery("SELECT Name, Query, QueryLanguage FROM __EventFilter"),
                null);
            foreach (ManagementObject obj in searcher.Get())
            {
                using (obj)
                {
                    if (filters.Count >= MaxRows)
                    {
                        return true;
                    }

                    filters.Add(MapFilter(ReadProps(obj)));
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or COMException)
        {
            gaps.Add(new CollectionGap("__EventFilter", "ShelfUnreadable", ex.GetType().Name));
        }

        return false;
    }

    private static bool QueryBindings(
        ManagementScope scope, List<WmiBindingRecord> bindings, List<CollectionGap> gaps)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                scope, new ObjectQuery("SELECT Filter, Consumer FROM __FilterToConsumerBinding"),
                null);
            foreach (ManagementObject obj in searcher.Get())
            {
                using (obj)
                {
                    if (bindings.Count >= MaxRows)
                    {
                        return true;
                    }

                    bindings.Add(MapBinding(ReadProps(obj)));
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or COMException)
        {
            gaps.Add(new CollectionGap("__FilterToConsumerBinding", "ShelfUnreadable", ex.GetType().Name));
        }

        return false;
    }

    private static Dictionary<string, object?> ReadProps(ManagementObject obj)
    {
        var props = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (var prop in obj.Properties)
        {
            try
            {
                props[prop.Name] = prop.Value;
            }
            catch
            {
                props[prop.Name] = null;
            }
        }

        return props;
    }

    // Pure row mappers (unit-tested over dictionaries; the live
    // query only feeds them).
    internal static WmiFilterRecord MapFilter(IReadOnlyDictionary<string, object?> props) =>
        new(Str(props, "Name") ?? "(unnamed filter)",
            Str(props, "Query"), Str(props, "QueryLanguage"));

    internal static WmiBindingRecord MapBinding(IReadOnlyDictionary<string, object?> props) =>
        new(ShortRef(Str(props, "Filter")), ShortRef(Str(props, "Consumer")));

    private static string? Str(IReadOnlyDictionary<string, object?> props, string key) =>
        props.TryGetValue(key, out var value) ? value?.ToString()?.Trim() : null;

    // Consumer/Filter refs are full WMI paths — keep the tail
    // (class + key) so rows stay readable; the full path is one
    // wbemtest away for an analyst.
    private static string ShortRef(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return "(unresolved)";
        }

        int colon = path.LastIndexOf(':');
        string tail = colon >= 0 ? path.Substring(colon + 1) : path;
        return tail.Length <= 160 ? tail : tail[..160];
    }
}
