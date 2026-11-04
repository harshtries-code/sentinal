using Sentinel.Store;

namespace Sentinel.Engine.Policy;

// One duplicate set: copies ordered best-first. CopiesOrdered[0] is
// the "real one" (01 §5.2): app-owned locations beat user files,
// user files beat downloads/temp, the bin always loses; ties break
// by newest mtime, then shortest path. Callers show the primary as
// KEEP and the rest as REVIEW candidates — never auto-picked SAFE.
public sealed record DuplicateGroup(
    string Hash,
    long SizeBytes,
    int CopyCount,
    IReadOnlyList<string> CopiesOrdered);

// Duplicate grouping (01 §5.2): exact-hash sets only. No fuzzy
// matching, no content inspection beyond the stored fingerprint
// hash. Pure: fingerprints in, groups out.
public static class DuplicateFinder
{
    public const long DefaultMinBytes = 4096;

    // Where one copy stands in keeper order (P23): a preferred
    // (app-owned) root beats an unlisted location, unlisted beats a
    // last-resort root (downloads/temp), the bin always loses.
    public enum CopyRankKind
    {
        Preferred,
        Other,
        Last,
        Bin,
    }

    public sealed record CopyRank(CopyRankKind Kind, int Index);

    public static IReadOnlyList<DuplicateGroup> FindByHash(
        IEnumerable<Fingerprint> files,
        IReadOnlyList<string> preferredRoots,
        long minBytes = DefaultMinBytes,
        IReadOnlyList<string>? lastRoots = null)
    {
        var roots = NormalizeRoots(preferredRoots);
        var lasts = NormalizeRoots(lastRoots ?? []);

        return files
            .Where(f => f.Hash is not null && f.Size >= minBytes)
            .GroupBy(f => f.Hash!)
            .Where(g => g.Select(f => Norm(f.Path)).Distinct(StringComparer.Ordinal).Count() > 1)
            .Select(g =>
            {
                var ordered = g
                    .OrderBy(f => Rank(Norm(f.Path), roots, lasts))
                    .ThenByDescending(f => f.MTimeUtcTicks)
                    .ThenBy(f => f.Path.Length)
                    .Select(f => f.Path)
                    .ToList();
                var first = g.First();
                return new DuplicateGroup(first.Hash!, first.Size, ordered.Count, ordered);
            })
            .OrderByDescending(g => g.SizeBytes * g.CopyCount)
            .ToList();
    }

    public static CopyRank RankCopy(
        string path, IReadOnlyList<string> preferredRoots,
        IReadOnlyList<string>? lastRoots = null)
    {
        string norm = Norm(path);
        var roots = NormalizeRoots(preferredRoots);
        var lasts = NormalizeRoots(lastRoots ?? []);
        if (norm.Contains(@"$Recycle.Bin\", StringComparison.OrdinalIgnoreCase))
        {
            return new CopyRank(CopyRankKind.Bin, -1);
        }

        for (int i = 0; i < roots.Length; i++)
        {
            if (Under(norm, roots[i]))
            {
                return new CopyRank(CopyRankKind.Preferred, i);
            }
        }

        for (int i = 0; i < lasts.Length; i++)
        {
            if (Under(norm, lasts[i]))
            {
                return new CopyRank(CopyRankKind.Last, i);
            }
        }

        return new CopyRank(CopyRankKind.Other, -1);
    }

    private static int Rank(string path, string[] roots, string[] lasts)
    {
        if (path.Contains(@"$Recycle.Bin\", StringComparison.OrdinalIgnoreCase))
        {
            return int.MaxValue; // The bin is never the "real one".
        }

        for (int i = 0; i < roots.Length; i++)
        {
            if (Under(path, roots[i]))
            {
                return i;
            }
        }

        for (int i = 0; i < lasts.Length; i++)
        {
            if (Under(path, lasts[i]))
            {
                return roots.Length + 1 + i;
            }
        }

        return roots.Length;
    }

    private static bool Under(string path, string root) =>
        root.Length > 0
        && (path.Equals(root, StringComparison.Ordinal)
            || path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal));

    private static string[] NormalizeRoots(IReadOnlyList<string> roots) =>
        roots
            .Select(r =>
            {
                try
                {
                    return Path.GetFullPath(r).TrimEnd(Path.DirectorySeparatorChar).ToUpperInvariant();
                }
                catch
                {
                    return r.Trim().ToUpperInvariant();
                }
            })
            .ToArray();

    private static string Norm(string path)
    {
        try
        {
            return Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar).ToUpperInvariant();
        }
        catch
        {
            return path.Trim().ToUpperInvariant();
        }
    }
}
