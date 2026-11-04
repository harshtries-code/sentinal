using Sentinel.Store;

namespace Sentinel.Engine.Policy;

// One copy's standing in a duplicate set (P23): keeper-first order
// plus the plain-language reasons behind it. The keeper is a
// SUGGESTION for review — never an auto-delete pick. Identical
// bytes prove identical contents, never that a copy is unwanted.
public sealed record CopyAssessment(
    string Path,
    long MTimeUtcTicks,
    string? Tier,
    bool IsKeeper,
    IReadOnlyList<string> Reasons);

public sealed record DuplicateComparison(
    string Hash,
    long SizeBytes,
    IReadOnlyList<CopyAssessment> CopiesOrdered);

// Keeper reasoning (01 §5.2, R12). Pure: inventory members in,
// ordered assessments out. Ordering matches DuplicateFinder
// (preferred app roots, then unlisted locations, then
// downloads/temp, bin last; ties by newest mtime, then shortest
// path). Ownership comes from the uninstall match, never a guess.
public static class DuplicateComparer
{
    public static DuplicateComparison Compare(
        string hash,
        long sizeBytes,
        IReadOnlyList<Fingerprint> members,
        IReadOnlyList<string> preferredRoots,
        IReadOnlyList<string>? lastRoots,
        IReadOnlyList<UninstallEntry> uninstall)
    {
        var ordered = members
            .OrderBy(m => RankValue(m.Path, preferredRoots, lastRoots))
            .ThenByDescending(m => m.MTimeUtcTicks)
            .ThenBy(m => m.Path.Length)
            .ToList();
        long newest = ordered.Count == 0
            ? 0
            : ordered.Max(m => m.MTimeUtcTicks);
        int newestCount = ordered.Count(m => m.MTimeUtcTicks == newest);

        var copies = new List<CopyAssessment>(ordered.Count);
        for (int i = 0; i < ordered.Count; i++)
        {
            var member = ordered[i];
            var rank = DuplicateFinder.RankCopy(
                member.Path, preferredRoots, lastRoots);
            var reasons = new List<string>
            {
                LocationReason(rank, preferredRoots, lastRoots ?? []),
                OwnerReason(member.Path, uninstall),
                TierReason(member.Tier),
            };
            if (ordered.Count > 1 && member.MTimeUtcTicks == newest && newestCount == 1)
            {
                reasons.Add("Newest copy.");
            }

            copies.Add(new CopyAssessment(
                member.Path, member.MTimeUtcTicks, member.Tier,
                i == 0, reasons));
        }

        return new DuplicateComparison(hash, sizeBytes, copies);
    }

    private static int RankValue(
        string path, IReadOnlyList<string> preferredRoots,
        IReadOnlyList<string>? lastRoots)
    {
        var rank = DuplicateFinder.RankCopy(path, preferredRoots, lastRoots);
        return rank.Kind switch
        {
            DuplicateFinder.CopyRankKind.Preferred => rank.Index,
            DuplicateFinder.CopyRankKind.Other => preferredRoots.Count,
            DuplicateFinder.CopyRankKind.Last => preferredRoots.Count + 1 + rank.Index,
            _ => int.MaxValue,
        };
    }

    private static string LocationReason(
        DuplicateFinder.CopyRank rank,
        IReadOnlyList<string> preferredRoots,
        IReadOnlyList<string> lastRoots) =>
        rank.Kind switch
        {
            DuplicateFinder.CopyRankKind.Bin =>
                "Already in the Recycle Bin — permanent deletion needs your call.",
            DuplicateFinder.CopyRankKind.Preferred =>
                $"Inside {Leaf(preferredRoots, rank.Index)} — an app-owned location.",
            DuplicateFinder.CopyRankKind.Last =>
                $"Inside {Leaf(lastRoots, rank.Index)} — downloads and temp rank last.",
            _ => "Outside known app folders.",
        };

    private static string OwnerReason(string path, IReadOnlyList<UninstallEntry> uninstall)
    {
        string dir;
        try
        {
            dir = Path.GetDirectoryName(path) ?? path;
        }
        catch
        {
            dir = path;
        }

        var entry = OrphanHunter.FindEntry(dir, uninstall);
        return entry is null
            ? "No installed app claims this folder."
            : $"Claimed by {entry.DisplayName}.";
    }

    private static string TierReason(string? tier) =>
        tier?.ToUpperInvariant() switch
        {
            "NEVER" => "Protected (Never Touch) — removing needs your explicit call.",
            "REVIEW" => "Marked for review.",
            "SAFE" => "Marked safe.",
            _ => "Not yet classified.",
        };

    private static string Leaf(IReadOnlyList<string> roots, int index)
    {
        if (index < 0 || index >= roots.Count)
        {
            return "a known folder";
        }

        try
        {
            string leaf = Path.GetFileName(
                roots[index].TrimEnd(
                    Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            return string.IsNullOrEmpty(leaf) ? roots[index] : leaf;
        }
        catch
        {
            return roots[index];
        }
    }
}
