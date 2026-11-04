using System.Diagnostics;
using System.Security.Cryptography;
using Sentinel.Engine.Scan;
using Sentinel.Store;

namespace Sentinel.Engine.Inventory;

// READ-ONLY BY CONSTRUCTION: this class opens scanned files with
// read+share access only. It contains no write/delete/create call
// against any scanned path. Junctions and symlinks are never
// followed; cloud placeholders are recorded, never hydrated.
public sealed class DiskInventoryScanner
{
    private readonly SentinelDb _db;

    public DiskInventoryScanner(SentinelDb db)
    {
        _db = db;
    }

    // P22: scan-time classification. When the orchestrator sets a
    // classifier (frozen never-list + frozen clock per scan), every
    // upsert carries a tier computed from the exact stat just read —
    // zero extra writes. Null (tests, legacy paths) leaves tiers to
    // the Collect-time pass. No orphan predicate here: leftovers
    // classify NEVER (conservative) until the orphan pass carves
    // them into REVIEW.
    public Sentinel.Engine.Policy.RiskClassifier? Classifier { get; set; }

    public DateTime ClassifyUtcNow { get; set; } = DateTime.UtcNow;

    public async Task<InventoryResult> ScanAsync(
        string root,
        int generation,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        _db.BeginBulk();
        var runId = _db.BeginRun(root, generation, "Unknown");
        var gaps = new List<InventoryGap>();
        int filesSeen = 0;
        int filesHashed = 0;
        long bytesSeen = 0L;

        bool committed = false;
        try
        {
            var dirListings = new List<DirListing>();
            foreach (var file in FileEnumerator.Enumerate(root, gaps, ct, null, dirListings))
            {
                ct.ThrowIfCancellationRequested();
                var outcome = await ProcessFileAsync(file, generation, ct).ConfigureAwait(false);
                if (outcome.Gap is not null)
                {
                    gaps.Add(outcome.Gap);
                }

                if (!outcome.Counted)
                {
                    continue;
                }

                filesSeen++;
                bytesSeen += outcome.Size;
                if (outcome.Hashed)
                {
                    filesHashed++;
                }
            }

            sw.Stop();
            // Reached only when enumeration completed: reconcile
            // deletions for this scope (P1-03). Gaps protect their
            // subtrees; a root-level gap disables the purge.
            _db.DeleteFingerprintsNotSeenIn(
                root, generation, gaps.Select(g => g.Path).ToList());
            // P23: rewrite this scope's directory census. A
            // root-level gap means the listing never started — the
            // stale census is kept, never blanked on a blind run.
            if (!HasRootGap(root, gaps))
            {
                _db.ReplaceDirStats(root, ToDirStats(dirListings), generation);
            }
            _db.EndRun(runId, filesSeen, bytesSeen, filesHashed, sw.ElapsedMilliseconds,
                "Completed", null, gaps.Count);
            _db.EndBulk(commit: true);
            committed = true;
        }
        finally
        {
            if (!committed)
            {
                _db.EndBulk(commit: false);
            }
        }

        return new InventoryResult(runId, generation, filesSeen, bytesSeen, filesHashed, gaps, sw.Elapsed);
    }

    // A hash is only stored when the file is byte-identical before
    // and after the read. Anything else is an unstable observation,
    // never a verified fingerprint.
    public static bool IsStable(long preSize, long preMtime, long postSize, long postMtime)
    {
        return preSize == postSize && preMtime == postMtime;
    }

    // Single-file pipeline shared by full scans and delta rescans.
    // Returns the gap instead of throwing: one bad file never kills a scan.
    internal async Task<FileOutcome> ProcessFileAsync(
        string file,
        int generation,
        CancellationToken ct,
        PauseToken? pause = null)
    {
        FileAttributes attr;
        try
        {
            attr = File.GetAttributes(file);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new FileOutcome(0, 0, false, new InventoryGap(file, ex.GetType().Name), Counted: false);
        }

        if ((attr & FileAttributes.Directory) != 0)
        {
            return new FileOutcome(0, 0, false, new InventoryGap(file, "NotAFile"), Counted: false);
        }

        if ((attr & FileAttributes.ReparsePoint) != 0)
        {
            return new FileOutcome(0, 0, false, new InventoryGap(file, "FileLinkSkipped"), Counted: false);
        }

        FileInfo info;
        try
        {
            info = new FileInfo(file);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new FileOutcome(0, 0, false, new InventoryGap(file, ex.GetType().Name), Counted: false);
        }

        (long size, long mtimeTicks, bool placeholder, int flags) pre;
        try
        {
            info.Refresh();
            int flags = ComputeAttrFlags(attr);

            pre = (info.Length, info.LastWriteTimeUtc.Ticks,
                (info.Attributes & FileAttributes.Offline) != 0, flags);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new FileOutcome(0, 0, false, new InventoryGap(file, ex.GetType().Name), Counted: false);
        }

        // P23 dead-shortcut probe: .lnk only, bounded prefix read,
        // target-existence stat only (the target is never opened).
        // Unparseable/unreadable/network targets yield no signal —
        // unknown is never reported as dead.
        var probe = ProbeDeadLink(file);
        int attrFlags = pre.flags | (probe.IsDead ? FingerprintAttrs.DeadShortcut : 0);
        if (probe.IsDead && probe.Target is not null)
        {
            _db.UpsertDeadLink(file, probe.Target);
        }
        else if (file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
        {
            _db.DeleteDeadLink(file);
        }

        var existing = _db.GetFingerprint(file);
        bool changed = existing is null
            || existing.Size != pre.size
            || existing.MTimeUtcTicks != pre.mtimeTicks
            || existing.Hash is null; // Missing hash is re-attempted, never trusted.

        string? hash = existing?.Hash;
        bool hashed = false;
        if (changed && !pre.placeholder)
        {
            string fresh;
            try
            {
                fresh = await HashFileAsync(file, ct, pause).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Metadata and hashing are SEPARATE facts: the stat is
                // current (the file did not move; the read failed), so
                // the known size/mtime are stored with a MISSING hash
                // and counted. The gap records the failed deep read.
                var failedTier = ClassifyNow(file, pre.size, pre.mtimeTicks, attrFlags);
                _db.UpsertFingerprint(file, pre.size, pre.mtimeTicks, null, generation, attrFlags,
                    failedTier.Tier, failedTier.Regrowth, generation, failedTier.HasTier);
                return new FileOutcome(
                    pre.size, pre.mtimeTicks, false,
                    new InventoryGap(file, "HashFailed:" + ex.GetType().Name),
                    Counted: true);
            }

            (long size, long mtimeTicks) post;
            try
            {
                info.Refresh();
                post = (info.Length, info.LastWriteTimeUtc.Ticks);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return new FileOutcome(0, 0, false, new InventoryGap(file, ex.GetType().Name), Counted: false);
            }

            if (!IsStable(pre.size, pre.mtimeTicks, post.size, post.mtimeTicks))
            {
                // The file moved under us: keep the OLD fingerprint row
                // (or none) rather than storing a hash against a wrong
                // stat. The pre-read size is NOT current, so it is NOT
                // counted: unknown size is never presented as observed.
                return new FileOutcome(0, 0, false, new InventoryGap(file, "UnstableDuringRead"), Counted: false);
            }

            hash = fresh;
            hashed = true;
        }

        var tier = ClassifyNow(file, pre.size, pre.mtimeTicks, attrFlags);
        _db.UpsertFingerprint(file, pre.size, pre.mtimeTicks, hash, generation, attrFlags,
            tier.Tier, tier.Regrowth, generation, tier.HasTier);
        return new FileOutcome(pre.size, pre.mtimeTicks, hashed, null, Counted: true);
    }

    // Chunked so pause (<1s) and cancel work inside multi-GB files,
    // not just between them. Read-only: open/read/share, nothing else.
    private static async Task<string> HashFileAsync(string path, CancellationToken ct, PauseToken? pause)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 81920,
            useAsync: true);
        using var incremental = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        int read;
        while ((read = await stream.ReadAsync(buffer.AsMemory(), ct).ConfigureAwait(false)) > 0)
        {
            if (pause is not null)
            {
                await pause.WaitIfPausedAsync(ct).ConfigureAwait(false);
            }

            incremental.AppendData(buffer.AsSpan(0, read));
        }

        return Convert.ToHexString(incremental.GetHashAndReset());
    }

    internal static int ComputeAttrFlags(FileAttributes attr)
    {
        int flags = 0;
        if ((attr & FileAttributes.SparseFile) != 0)
        {
            flags |= FingerprintAttrs.Sparse;
        }

        if ((attr & FileAttributes.Offline) != 0)
        {
            flags |= FingerprintAttrs.Placeholder;
        }

        return flags;
    }

    private (string? Tier, string? Regrowth, bool HasTier) ClassifyNow(
        string file, long size, long mtimeTicks, int attrFlags)
    {
        if (Classifier is null)
        {
            return (null, null, false);
        }

        var c = Classifier.Classify(
            new Fingerprint(file, size, mtimeTicks, null, 0, AttrFlags: attrFlags),
            ClassifyUtcNow, null);
        return (c.Tier.ToString().ToUpperInvariant(), c.ExpectedRegrowth, true);
    }

    internal static bool HasRootGap(string root, IReadOnlyList<InventoryGap> gaps)
    {
        // Root gaps record the canonicalized root; match both forms.
        string full;
        try
        {
            full = Path.GetFullPath(root);
        }
        catch
        {
            full = root;
        }

        foreach (var gap in gaps)
        {
            if (gap.Path.Equals(root, StringComparison.OrdinalIgnoreCase)
                || gap.Path.Equals(full, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    internal static IReadOnlyList<DirStat> ToDirStats(IReadOnlyList<DirListing> listings)
    {
        var rows = new List<DirStat>(listings.Count);
        foreach (var listing in listings)
        {
            rows.Add(new DirStat(
                listing.Dir, listing.DirectFiles, listing.DirectSubdirs,
                listing.DirectUnverified, listing.MtimeTicks, 0));
        }

        return rows;
    }

    // Counted is independent of Gap: a file with known current
    // metadata counts toward files/bytes even when its deeper read
    // (hash) failed. Nothing with unknown size is ever counted.
    internal sealed record FileOutcome(
        long Size, long MTimeUtcTicks, bool Hashed, InventoryGap? Gap, bool Counted);

    internal sealed record DeadLinkProbe(bool IsDead, string? Target);

    internal static DeadLinkProbe ProbeDeadLink(string file)
    {
        if (!file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
        {
            return new DeadLinkProbe(false, null);
        }

        byte[] prefix;
        try
        {
            using var stream = new FileStream(
                file,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 4096,
                useAsync: false);
            long want = Math.Min(stream.Length, Policy.ShortcutResolver.MaxProbeBytes);
            prefix = new byte[want];
            int read = 0;
            while (read < want)
            {
                int n = stream.Read(prefix, read, (int)want - read);
                if (n == 0)
                {
                    break;
                }

                read += n;
            }

            if (read != want)
            {
                Array.Resize(ref prefix, read);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new DeadLinkProbe(false, null);
        }

        string? target = Policy.ShortcutResolver.TryGetLocalTarget(prefix);
        if (target is null)
        {
            return new DeadLinkProbe(false, null);
        }

        bool exists;
        try
        {
            exists = File.Exists(target) || Directory.Exists(target);
        }
        catch
        {
            exists = true; // The check itself failed: never claim dead.
        }

        return exists
            ? new DeadLinkProbe(false, null)
            : new DeadLinkProbe(true, target);
    }
}
