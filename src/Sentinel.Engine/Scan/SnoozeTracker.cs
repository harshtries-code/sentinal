namespace Sentinel.Engine.Scan;

// Identical finding + identical evidence is emitted once, then
// snoozed until the evidence changes or the cooldown expires.
// In-memory for Phase 1; Phase 2 persists it in the Passport.
public sealed class SnoozeTracker
{
    private readonly Dictionary<string, (string EvidenceHash, DateTime UntilUtc)> _map = new();
    private readonly object _gate = new();

    public bool ShouldEmit(string key, string evidenceHash, TimeSpan cooldown, DateTime utcNow)
    {
        lock (_gate)
        {
            if (_map.TryGetValue(key, out var entry)
                && entry.EvidenceHash == evidenceHash
                && utcNow < entry.UntilUtc)
            {
                return false;
            }

            _map[key] = (evidenceHash, utcNow + cooldown);
            return true;
        }
    }

    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _map.Count;
            }
        }
    }

    // P21: forget one key (PID-reuse drop releases a verdict
    // that never published). Removing an absent key is a no-op.
    public void Forget(string key)
    {
        lock (_gate)
        {
            _map.Remove(key);
        }
    }

    // P21: strictly bound the map. Past maxEntries, expired keys
    // go first; if still over, the oldest-expiring half goes. PID
    // death does NOT forget (01 §5.8: identical finding + identical
    // evidence stays snoozed until evidence changes or cooldown
    // expires) — this prune is the size backstop instead.
    public void PruneExpired(DateTime utcNow, int maxEntries)
    {
        lock (_gate)
        {
            if (_map.Count <= maxEntries)
            {
                return;
            }

            foreach (var key in _map.Where(kv => utcNow >= kv.Value.UntilUtc).Select(kv => kv.Key).ToList())
            {
                _map.Remove(key);
            }

            if (_map.Count > maxEntries)
            {
                foreach (var key in _map.OrderBy(kv => kv.Value.UntilUtc).Take(_map.Count / 2).Select(kv => kv.Key).ToList())
                {
                    _map.Remove(key);
                }
            }
        }
    }
}
