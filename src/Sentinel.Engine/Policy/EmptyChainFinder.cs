using Sentinel.Store;

namespace Sentinel.Engine.Policy;

// One maximal empty directory chain (P23): Dir holds no files and
// every verified descendant holds none either, up to Depth levels
// deep. The parent (if any) is non-empty or unverified, so each
// wasted chain reports once, at its top.
public sealed record EmptyChain(string Dir, long MtimeTicks, int Depth);

// Bottom-up empty-chain fold over the directory census (01 §5.2).
// Pure: rows in, chain roots out. Strictly conservative: a
// directory qualifies only when its row exists (fully listed),
// DirectFiles and DirectUnverified are 0, EVERY counted subdir has
// its own row, and every subdir qualifies. Links, exclusions,
// unreadable entries, and unlisted subtrees disqualify their
// ancestors — never assumed empty.
public static class EmptyChainFinder
{
    public static IReadOnlyList<EmptyChain> FindChains(IReadOnlyList<DirStat> rows)
    {
        var byKey = new Dictionary<string, DirStat>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            byKey[Key(row.Dir)] = row;
        }

        var childrenOf = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            string? parent = ParentKey(row.Dir);
            if (parent is null)
            {
                continue;
            }

            if (!childrenOf.TryGetValue(parent, out var kids))
            {
                kids = [];
                childrenOf[parent] = kids;
            }

            kids.Add(Key(row.Dir));
        }

        // Iterative bottom-up: a child path is strictly longer than
        // its parent, so longest-first order evaluates every child
        // before its parent. No recursion at any depth.
        var member = new Dictionary<string, bool>(StringComparer.Ordinal);
        var ordered = byKey.Keys.OrderByDescending(k => k.Length).ToList();
        foreach (var key in ordered)
        {
            var row = byKey[key];
            if (row.DirectFiles != 0 || row.DirectUnverified != 0)
            {
                member[key] = false;
                continue;
            }

            childrenOf.TryGetValue(key, out var kids);
            int verified = kids?.Count ?? 0;
            if (verified != row.DirectSubdirs)
            {
                member[key] = false;
                continue;
            }

            bool allEmpty = true;
            if (kids is not null)
            {
                foreach (var kid in kids)
                {
                    if (!member.TryGetValue(kid, out bool kidEmpty) || !kidEmpty)
                    {
                        allEmpty = false;
                        break;
                    }
                }
            }

            member[key] = allEmpty;
        }

        bool IsMember(string key) =>
            member.TryGetValue(key, out bool known) && known;

        int Depth(string key)
        {
            // Iterative: pathological depth never overflows the stack.
            int deep = 1;
            var stack = new Stack<(string Key, int Level)>();
            stack.Push((key, 1));
            while (stack.Count > 0)
            {
                var (next, level) = stack.Pop();
                deep = Math.Max(deep, level);
                if (childrenOf.TryGetValue(next, out var kids))
                {
                    foreach (var kid in kids)
                    {
                        stack.Push((kid, level + 1));
                    }
                }
            }

            return deep;
        }

        var chains = new List<EmptyChain>();
        foreach (var row in rows)
        {
            string key = Key(row.Dir);
            if (!IsMember(key))
            {
                continue;
            }

            string? parent = ParentKey(row.Dir);
            if (parent is not null && byKey.ContainsKey(parent) && IsMember(parent))
            {
                continue; // Reported once, at the chain top.
            }

            chains.Add(new EmptyChain(row.Dir, row.MtimeTicks, Depth(key)));
        }

        return chains.OrderBy(c => c.Dir, StringComparer.OrdinalIgnoreCase).ToList();
    }

    // Sorted live file-parent set: answers "does any CURRENT
    // fingerprint sit at or under this dir" in O(log n) per chain,
    // so a delta-added file vetoes a stale census chain.
    public sealed class EmptyChainLiveSet
    {
        private readonly List<string> _parents;

        private EmptyChainLiveSet(List<string> parents)
        {
            _parents = parents;
        }

        public static EmptyChainLiveSet FromParents(IEnumerable<string> parentDirs)
        {
            var parents = parentDirs
                .Select(Key)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(k => k, StringComparer.Ordinal)
                .ToList();
            return new EmptyChainLiveSet(parents);
        }

        public bool HasFilesAtOrUnder(string dir)
        {
            string key = Key(dir);
            int i = _parents.BinarySearch(key, StringComparer.Ordinal);
            if (i >= 0)
            {
                return true;
            }

            int at = ~i;
            if (at < _parents.Count)
            {
                string prefix = key + Path.DirectorySeparatorChar;
                if (_parents[at].StartsWith(prefix, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }
    }

    private static string Key(string dir) =>
        dir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            .ToUpperInvariant();

    private static string? ParentKey(string dir)
    {
        string trimmed = dir.TrimEnd(
            Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string? parent = Path.GetDirectoryName(trimmed);
        if (string.IsNullOrEmpty(parent))
        {
            return null;
        }

        return Key(parent);
    }
}
