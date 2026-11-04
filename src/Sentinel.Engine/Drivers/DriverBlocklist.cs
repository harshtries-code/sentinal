using Sentinel.Store;

namespace Sentinel.Engine.Drivers;

// One blocked driver version: a version that failed verification or
// was rolled back is never offered again (D40 matching consults the
// key set). Backed by the Passport DriverBlocklist table (01 §5.3) —
// the sanctioned store, not a sidecar file — with a write-through
// memory cache: a dead database degrades to session memory (still
// blocking within the run) and the fault stays observable instead
// of wedging every driver flow.
public sealed record DriverBlockEntry(
    string Key,
    string Source,
    string Version,
    string? DeviceId,
    string Reason,
    string BlockedUtc);

public sealed class DriverBlocklist
{
    private readonly Func<PassportDb> _dbFactory;
    private readonly object _gate = new();
    private Dictionary<string, DriverBlockEntry>? _cache;

    public bool LoadedWithFault { get; private set; }

    public string? LoadFault { get; private set; }

    public DriverBlocklist(Func<PassportDb> dbFactory)
    {
        _dbFactory = dbFactory;
        // Eager: LoadedWithFault is meaningful immediately after
        // construction. Never throws — faults become the flag.
        lock (_gate)
        {
            EnsureLoadedLocked();
        }
    }

    public static string BlockKey(DriverSource source, string version) =>
        source + "|" + (version ?? string.Empty);

    public static string BlockKey(string source, string version) =>
        source + "|" + (version ?? string.Empty);

    // Canonicalizes approval-time source spellings to DriverSource
    // names. Mirrors the update executor's source switch exactly —
    // both must agree or blocks silently miss. Unknown spellings
    // return verbatim (trimmed): a misspelled source blocks nothing,
    // which is honest, while inventing a ladder source would corrupt
    // the key the matching consults.
    public static string CanonicalSource(string? source)
    {
        string s = (source ?? string.Empty).Trim();
        return s.ToLowerInvariant() switch
        {
            "windows-update" or "windowsupdate" or "wu" or "windows update" => nameof(DriverSource.WindowsUpdate),
            "oem-catalogue" or "oemcatalogue" or "oem" or "dell-dcu" or "dcu" or "oem catalogue" => nameof(DriverSource.OemCatalogue),
            "vendor-link-out" or "vendorlinkout" or "vendor link-out" or "link-out" or "linkout" => nameof(DriverSource.VendorLinkOut),
            _ when string.Equals(s, nameof(DriverSource.WindowsUpdate), StringComparison.OrdinalIgnoreCase) => nameof(DriverSource.WindowsUpdate),
            _ when string.Equals(s, nameof(DriverSource.OemCatalogue), StringComparison.OrdinalIgnoreCase) => nameof(DriverSource.OemCatalogue),
            _ when string.Equals(s, nameof(DriverSource.VendorLinkOut), StringComparison.OrdinalIgnoreCase) => nameof(DriverSource.VendorLinkOut),
            _ => s,
        };
    }

    public IReadOnlySet<string> Keys
    {
        get
        {
            lock (_gate)
            {
                return EnsureLoadedLocked().Keys.ToHashSet(StringComparer.Ordinal);
            }
        }
    }

    public IReadOnlyList<DriverBlockEntry> Entries
    {
        get
        {
            lock (_gate)
            {
                return EnsureLoadedLocked().Values.OrderBy(e => e.BlockedUtc).ToList();
            }
        }
    }

    public bool IsBlocked(DriverSource source, string version)
    {
        lock (_gate)
        {
            return EnsureLoadedLocked().ContainsKey(BlockKey(source, version));
        }
    }

    public void Add(DriverSource source, string version, string? deviceId, string reason) =>
        Add(source.ToString(), version, deviceId, reason);

    public void Add(string source, string version, string? deviceId, string reason)
    {
        source = CanonicalSource(source);
        string key = BlockKey(source, version);
        lock (_gate)
        {
            var cache = EnsureLoadedLocked();
            cache[key] = new DriverBlockEntry(key, source, version ?? string.Empty,
                deviceId, reason, DateTime.UtcNow.ToString("o"));
            try
            {
                using var db = _dbFactory();
                db.AddBlockedDriver(deviceId ?? string.Empty, version ?? string.Empty, source, reason);
            }
            catch (Exception ex)
            {
                NoteFaultLocked($"Driver blocklist write failed ({ex.GetType().Name}) — " +
                    "the block holds for this session only.");
            }
        }
    }

    // Operator unblock: removes EVERY row with this source|version
    // (matching blocks globally, so unblocking is global too).
    public bool Remove(string key)
    {
        lock (_gate)
        {
            var cache = EnsureLoadedLocked();
            if (!cache.Remove(key, out var entry))
            {
                return false;
            }

            try
            {
                using var db = _dbFactory();
                // The table keys by (device, version): delete every
                // row this key could have come from.
                foreach (var row in db.QueryBlockedDrivers(1000))
                {
                    if (string.Equals(BlockKey(row.Source, row.BadVersion), key, StringComparison.Ordinal))
                    {
                        db.RemoveBlockedDriver(row.DeviceKey, row.BadVersion);
                    }
                }
            }
            catch (Exception ex)
            {
                NoteFaultLocked($"Driver blocklist delete failed ({ex.GetType().Name}) — " +
                    "the removal holds for this session only.");
            }

            return true;
        }
    }

    private Dictionary<string, DriverBlockEntry> EnsureLoadedLocked()
    {
        if (_cache is not null)
        {
            return _cache;
        }

        var cache = new Dictionary<string, DriverBlockEntry>(StringComparer.Ordinal);
        try
        {
            using var db = _dbFactory();
            foreach (var row in db.QueryBlockedDrivers(1000))
            {
                string key = BlockKey(row.Source, row.BadVersion);
                cache.TryAdd(key, new DriverBlockEntry(key, row.Source, row.BadVersion,
                    string.IsNullOrEmpty(row.DeviceKey) ? null : row.DeviceKey,
                    row.Reason, row.AddedUtc));
            }
        }
        catch (Exception ex)
        {
            NoteFaultLocked($"Driver blocklist could not be read ({ex.GetType().Name}) — " +
                "starting empty. Previously blocked versions may be offered once more; " +
                "they will be re-blocked if they fail again.");
        }

        _cache = cache;
        return cache;
    }

    private void NoteFaultLocked(string fault)
    {
        LoadedWithFault = true;
        LoadFault = fault;
    }
}
