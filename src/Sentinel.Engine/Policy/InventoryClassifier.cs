using System.Security.Cryptography;
using System.Text;
using Sentinel.Store;

namespace Sentinel.Engine.Policy;

// P22: keeps every retained fingerprint classified without ever
// materializing the table. Two cached passes, both invalidated
// honestly instead of recomputed per page:
//
// - Orphan verdicts refresh when the inventory generation advanced
//   or the uninstall entries changed (Meta OrphanGen/OrphanHash).
// - Tier labels refresh incrementally: new rows and stat-changed
//   rows (Upsert NULLs their tier) every pass; ALL rows when the
//   Never Touch list changed (Meta NeverHash).
//
// Both passes are chunked + cancellable and report done/total.
public sealed record ClassifyProgress(long Done, long Total, string Phase);

public sealed class InventoryClassifier
{
    public const int ChunkSize = 2000;

    private readonly SentinelDb _db;
    private readonly string[] _neverList;

    public InventoryClassifier(SentinelDb db, IReadOnlyList<string> neverList)
    {
        _db = db;
        _neverList = neverList.ToArray();
    }

    public void EnsureClassified(
        DateTime utcNow, CancellationToken ct,
        Action<ClassifyProgress>? progress = null)
    {
        var uninstall = OrphanHunter.ReadUninstallEntries();
        EnsureOrphans(uninstall, utcNow, ct, progress);
        // Full cached list (paged read: the query clamps pages at
        // 500, so loop — a clipped orphan list would silently drop
        // the R-orphan carveout for the missing dirs).
        var orphans = new List<string>();
        int orphanOffset = 0;
        while (true)
        {
            var page = _db.QueryOrphanDirs(500, orphanOffset, out _);
            if (page.Count == 0)
            {
                break;
            }

            foreach (var o in page)
            {
                orphans.Add(o.Dir);
            }

            orphanOffset += page.Count;
            if (page.Count < 500)
            {
                break;
            }
        }
        bool IsOrphan(string normalizedPath) =>
            orphans.Any(d => normalizedPath.StartsWith(d, StringComparison.Ordinal));

        string neverHash = HashStrings(_neverList);
        int floor = _db.GetMeta("NeverHash") == neverHash ? 0 : int.MaxValue;
        long total = _db.CountUnclassified(floor);
        if (total == 0 && floor == 0)
        {
            return;
        }

        var classifier = new RiskClassifier(_neverList);
        int classGen = _db.GetMaxGeneration();
        long done = 0;
        string? after = null;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            var chunk = _db.QueryUnclassifiedChunk(after, ChunkSize, floor);
            if (chunk.Count == 0)
            {
                break;
            }

            var writes = new List<(string Path, string Tier, string? Regrowth, int ClassGen)>(chunk.Count);
            foreach (var fp in chunk)
            {
                var c = classifier.Classify(fp, utcNow, IsOrphan);
                writes.Add((fp.Path, c.Tier.ToString().ToUpperInvariant(), c.ExpectedRegrowth, classGen));
            }

            _db.UpdateClassifications(writes);
            done += chunk.Count;
            after = chunk[chunk.Count - 1].Path;
            progress?.Invoke(new ClassifyProgress(done, total, "tier"));
            if (chunk.Count < ChunkSize)
            {
                break;
            }
        }

        _db.SetMeta("NeverHash", neverHash);
    }

    private void EnsureOrphans(
        IReadOnlyList<UninstallEntry> uninstall, DateTime utcNow,
        CancellationToken ct, Action<ClassifyProgress>? progress)
    {
        int gen = _db.GetMaxGeneration();
        string entriesHash = HashStrings(uninstall
            .Select(u => u.DisplayName + "|" + u.InstallLocation + "|" + u.UninstallString)
            .OrderBy(s => s, StringComparer.Ordinal).ToList());
        if (_db.GetMeta("OrphanGen") == gen.ToString()
            && _db.GetMeta("OrphanHash") == entriesHash)
        {
            return;
        }

        var mtimes = _db.FoldDirectoryMtimes(ct);
        // P23: empty chains from the directory census. The census is
        // rewritten by full scans only, so every chain is
        // cross-checked against CURRENT fingerprint parents — a file
        // added by a delta (or a concurrently changed tree) vetoes
        // the chain. Stale census never overrules live files.
        var chains = EmptyChainFinder.FindChains(_db.QueryDirStats());
        var live = EmptyChainFinder.EmptyChainLiveSet.FromParents(mtimes.Keys);
        var verdicts = new List<(string Dir, long YoungestTicks, string Signals)>();
        long total = (long)mtimes.Count + chains.Count;
        long done = 0;
        foreach (var kv in mtimes)
        {
            ct.ThrowIfCancellationRequested();
            DateTime youngest = new DateTime(kv.Value, DateTimeKind.Utc);
            var verdict = OrphanHunter.Evaluate(kv.Key, youngest, utcNow, uninstall);
            if (verdict.IsPossibleLeftover)
            {
                try
                {
                    string norm = Path.GetFullPath(kv.Key)
                        .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                    verdicts.Add((norm.ToUpperInvariant(), kv.Value,
                        string.Join("; ", verdict.Signals)));
                }
                catch
                {
                    // Unusable dir form: skip, don't fail the pass.
                }
            }

            done++;
            if (done % 500 == 0)
            {
                progress?.Invoke(new ClassifyProgress(done, total, "orphans"));
            }
        }

        foreach (var chain in chains)
        {
            ct.ThrowIfCancellationRequested();
            done++;
            if (live.HasFilesAtOrUnder(chain.Dir))
            {
                continue;
            }

            DateTime youngest = new DateTime(chain.MtimeTicks, DateTimeKind.Utc);
            var verdict = OrphanHunter.Evaluate(chain.Dir, youngest, utcNow, uninstall);
            if (verdict.IsPossibleLeftover)
            {
                try
                {
                    string norm = Path.GetFullPath(chain.Dir)
                        .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                    var signals = verdict.Signals
                        .Concat(["EmptyChain", "Depth" + chain.Depth])
                        .ToList();
                    verdicts.Add((norm.ToUpperInvariant(), chain.MtimeTicks,
                        string.Join("; ", signals)));
                }
                catch
                {
                    // Unusable dir form: skip, don't fail the pass.
                }
            }

            if (done % 500 == 0)
            {
                progress?.Invoke(new ClassifyProgress(done, total, "orphans"));
            }
        }

        _db.ReplaceOrphanDirs(verdicts);
        _db.SetMeta("OrphanGen", gen.ToString());
        _db.SetMeta("OrphanHash", entriesHash);
        progress?.Invoke(new ClassifyProgress(done, total, "orphans"));
    }

    internal static string HashStrings(IReadOnlyList<string> values)
    {
        using var sha = SHA256.Create();
        var ordered = values.OrderBy(v => v, StringComparer.Ordinal).ToList();
        foreach (var v in ordered)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(v);
            sha.TransformBlock(bytes, 0, bytes.Length, null, 0);
            sha.TransformBlock([(byte)0], 0, 1, null, 0);
        }

        sha.TransformFinalBlock([], 0, 0);
        return Convert.ToHexString(sha.Hash!);
    }
}
