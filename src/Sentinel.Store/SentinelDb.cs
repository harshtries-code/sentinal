using Microsoft.Data.Sqlite;

namespace Sentinel.Store;

public sealed record Fingerprint(
    string Path,
    long Size,
    long MTimeUtcTicks,
    string? Hash,
    int LastSeenGeneration,
    string? Tier = null,
    string? Regrowth = null,
    int AttrFlags = 0,
    int ClassGen = 0);

// File-attribute facts recorded at stat time (P22 limits reporting).
// Bit values are stored in Fingerprints.AttrFlags.
public static class FingerprintAttrs
{
    public const int Sparse = 1;
    public const int Placeholder = 2;
    public const int DeadShortcut = 4;
}

// One bounded inventory question (P22): every filter is optional,
// every page is bounded, every answer carries its own totals and
// the generation it was read at. No SQL reaches callers.
public sealed record InventoryQuery(
    string? Tier = null,
    long? MinSize = null,
    long? MaxSize = null,
    string? Extension = null,
    string? NameContains = null,
    IReadOnlyList<string>? DirPrefixes = null,
    bool HashMissingOnly = false,
    bool RegrowingOnly = false,
    string Sort = "size",
    int Limit = 100,
    int Offset = 0);

public sealed record InventoryPage(
    IReadOnlyList<Fingerprint> Rows,
    long TotalMatches,
    long TotalBytes,
    int MaxGeneration);

public sealed record TierGroup(string Tier, long Files, long Bytes);

public sealed record ChildRollup(
    string Name, bool IsDir, long Files, long Bytes);

public sealed record DuplicateSet(
    string Hash, long SizeBytes, int Copies,
    IReadOnlyList<string> Paths);

// One fully-listed directory (P23): direct child counts observed by
// the enumerator plus the directory's own mtime. Empty-chain
// detection folds over these rows; a directory with no row was
// never verified and disqualifies its ancestors (never assumed).
public sealed record DirStat(
    string Dir, int DirectFiles, int DirectSubdirs, int DirectUnverified,
    long MtimeTicks, int Generation);

public sealed record AttrStats(
    long SparseFiles, long SparseBytes,
    long PlaceholderFiles, long PlaceholderBytes,
    long HashMissingFiles);

public sealed record ScanRunInfo(
    long Id,
    int Generation,
    string Root,
    string Status,
    string? Error,
    int FilesSeen,
    long BytesSeen,
    int FilesHashed,
    long DurationMs,
    int GapsCount,
    string StartedUtc,
    string Mode);

// P26: compatibility facade over the two-file layout. Every public
// signature is unchanged: run/coverage calls route to the Passport
// file, cache/inventory calls to the fingerprints file. Bulk mode
// opens a transaction on BOTH files and commits fingerprints FIRST
// (orphan fingerprints self-heal next generation; a run row
// without its fingerprints would claim phantom coverage).
// Direct per-file access is exposed for recovery, producers, and
// tests; new code should prefer the inner stores.
public sealed class SentinelDb : IDisposable
{
    private readonly object _gate = new();
    private bool _disposed;

    public string AnchorPath { get; }

    public string PassportPath { get; }

    public string FingerprintPath { get; }

    public PassportDb Passport { get; }

    public FingerprintDb Fingerprints { get; }

    public SentinelDb(string dbPath)
    {
        AnchorPath = dbPath;
        StoreLayout.EnsureSplit(dbPath);
        PassportPath = StoreLayout.DerivePassportPath(dbPath);
        FingerprintPath = StoreLayout.DeriveFingerprintPath(dbPath);
        PassportDb? passport = null;
        FingerprintDb? fingerprints = null;
        try
        {
            passport = new PassportDb(PassportPath);
            fingerprints = new FingerprintDb(FingerprintPath);
        }
        catch
        {
            // A08: a throwing constructor must not leak its open
            // handles — abandoned locks blocked quarantine moves
            // and later opens of the same files.
            try
            {
                fingerprints?.Dispose();
            }
            finally
            {
                passport?.Dispose();
            }

            SqliteConnection.ClearAllPools();
            throw;
        }

        Passport = passport;
        Fingerprints = fingerprints;
    }

    // A08: side-effect-free health probe over the whole layout.
    // Opens read-only; never migrates, never creates files. Null
    // when everything readable is healthy (missing files count as
    // healthy: nothing stored yet).
    public static string? ProbeHealth(string anchorPath)
    {
        string passportPath = StoreLayout.DerivePassportPath(anchorPath);
        if (File.Exists(anchorPath) && !File.Exists(passportPath))
        {
            // Legacy single file: one probe, old contract.
            if (StoreLayout.LooksLikeLegacyStore(anchorPath))
            {
                return null;
            }

            return ProbeLegacyDetail(anchorPath);
        }

        var problems = new List<string>();
        string? passport = PassportDb.ProbeHealth(passportPath);
        if (passport is not null)
        {
            problems.Add(Path.GetFileName(passportPath) + ": " + passport);
        }

        string? cache = FingerprintDb.ProbeHealth(
            StoreLayout.DeriveFingerprintPath(anchorPath));
        if (cache is not null)
        {
            problems.Add(
                Path.GetFileName(StoreLayout.DeriveFingerprintPath(anchorPath)) + ": " + cache);
        }

        return problems.Count == 0 ? null : string.Join("; ", problems);
    }

    private static string ProbeLegacyDetail(string anchorPath)
    {
        try
        {
            using var conn = new SqliteConnection(
                $"Data Source={anchorPath};Mode=ReadOnly;Pooling=false");
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM ScanRuns;";
            cmd.ExecuteScalar();
            cmd.CommandText = "SELECT COUNT(*) FROM Fingerprints;";
            cmd.ExecuteScalar();
            return "legacy store has no Sentinel tables";
        }
        catch (Exception ex)
        {
            return ex.GetType().Name + ": " + ex.Message.Split('\n')[0];
        }
    }

    public void BeginBulk()
    {
        lock (_gate)
        {
            Passport.BeginBulk();
            Fingerprints.BeginBulk();
        }
    }

    public void EndBulk(bool commit = true)
    {
        lock (_gate)
        {
            if (commit)
            {
                try
                {
                    Fingerprints.EndBulk(commit: true);
                }
                catch
                {
                    try
                    {
                        Passport.EndBulk(commit: false);
                    }
                    catch
                    {
                    }

                    throw;
                }

                Passport.EndBulk(commit: true);
            }
            else
            {
                try
                {
                    Fingerprints.EndBulk(commit: false);
                }
                finally
                {
                    Passport.EndBulk(commit: false);
                }
            }
        }
    }

    public int GetMaxGeneration()
    {
        lock (_gate)
        {
            return Passport.GetMaxGeneration();
        }
    }

    public long BeginRun(string root, int generation, string mode)
    {
        lock (_gate)
        {
            return Passport.BeginRun(root, generation, mode);
        }
    }

    public void EndRun(
        long runId,
        int filesSeen,
        long bytesSeen,
        int filesHashed,
        long durationMs,
        string status = "Completed",
        string? error = null,
        int gapsCount = 0)
    {
        lock (_gate)
        {
            Passport.EndRun(
                runId, filesSeen, bytesSeen, filesHashed, durationMs,
                status, error, gapsCount);
        }
    }

    public long RecordAbortedRun(
        string root,
        int generation,
        int filesSeen,
        long bytesSeen,
        int filesHashed,
        long durationMs,
        string status,
        string? error,
        string mode)
    {
        lock (_gate)
        {
            return Passport.RecordAbortedRun(
                root, generation, filesSeen, bytesSeen, filesHashed,
                durationMs, status, error, mode);
        }
    }

    public ScanRunInfo? GetRun(long runId)
    {
        lock (_gate)
        {
            return Passport.GetRun(runId);
        }
    }

    public IReadOnlyList<ScanRunInfo> ListRuns(int limit = 50)
    {
        lock (_gate)
        {
            return Passport.ListRuns(limit);
        }
    }

    public string? GetMeta(string key)
    {
        lock (_gate)
        {
            return Fingerprints.GetMeta(key);
        }
    }

    public void SetMeta(string key, string value)
    {
        lock (_gate)
        {
            Fingerprints.SetMeta(key, value);
        }
    }

    public Fingerprint? GetFingerprint(string path)
    {
        lock (_gate)
        {
            return Fingerprints.GetFingerprint(path);
        }
    }

    public long CountFingerprints()
    {
        lock (_gate)
        {
            return Fingerprints.CountFingerprints();
        }
    }

    public long SumFingerprintBytes()
    {
        lock (_gate)
        {
            return Fingerprints.SumFingerprintBytes();
        }
    }

    public IReadOnlyList<Fingerprint> ListLargestFingerprints(int limit = 5000)
    {
        lock (_gate)
        {
            return Fingerprints.ListLargestFingerprints(limit);
        }
    }

    public int DeleteFingerprintsNotSeenIn(
        string root, int generation, IReadOnlyList<string> gapPaths)
    {
        lock (_gate)
        {
            return Fingerprints.DeleteFingerprintsNotSeenIn(root, generation, gapPaths);
        }
    }

    public void ClearFingerprints()
    {
        lock (_gate)
        {
            Fingerprints.ClearFingerprints();
        }
    }

    public void UpsertFingerprint(
        string path, long size, long mtimeTicks, string? hash, int generation, int attrFlags = 0,
        string? tier = null, string? regrowth = null, int classGen = 0, bool hasTier = false)
    {
        lock (_gate)
        {
            Fingerprints.UpsertFingerprint(
                path, size, mtimeTicks, hash, generation, attrFlags,
                tier, regrowth, classGen, hasTier);
        }
    }

    public void SetClassification(string path, string tier, string? regrowth, int classGen)
    {
        lock (_gate)
        {
            Fingerprints.SetClassification(path, tier, regrowth, classGen);
        }
    }

    public IReadOnlyList<Fingerprint> QueryUnclassifiedChunk(
        string? afterPath, int limit, int classGenFloor)
    {
        lock (_gate)
        {
            return Fingerprints.QueryUnclassifiedChunk(afterPath, limit, classGenFloor);
        }
    }

    public long CountUnclassified(int classGenFloor)
    {
        lock (_gate)
        {
            return Fingerprints.CountUnclassified(classGenFloor);
        }
    }

    public void UpdateClassifications(
        IReadOnlyList<(string Path, string Tier, string? Regrowth, int ClassGen)> chunk)
    {
        lock (_gate)
        {
            Fingerprints.UpdateClassifications(chunk);
        }
    }

    public InventoryPage QueryInventoryPage(InventoryQuery q)
    {
        lock (_gate)
        {
            return Fingerprints.QueryInventoryPage(q);
        }
    }

    public IReadOnlyList<TierGroup> CountGroupByTier()
    {
        lock (_gate)
        {
            return Fingerprints.CountGroupByTier();
        }
    }

    public IReadOnlyDictionary<string, (long Files, long Bytes)> SumBuckets(
        IReadOnlyList<(string Key, string Dir)> buckets, string restKey)
    {
        lock (_gate)
        {
            return Fingerprints.SumBuckets(buckets, restKey);
        }
    }

    public IReadOnlyList<ChildRollup> QueryChildRollup(string dirPrefix, CancellationToken ct)
    {
        lock (_gate)
        {
            return Fingerprints.QueryChildRollup(dirPrefix, ct);
        }
    }

    public (IReadOnlyList<DuplicateSet> Sets, long TotalSets, long TotalWasted) QueryDuplicateSets(
        int limit, int offset, string? nameContains = null,
        IReadOnlyList<string>? dirPrefixes = null)
    {
        lock (_gate)
        {
            return Fingerprints.QueryDuplicateSets(limit, offset, nameContains, dirPrefixes);
        }
    }

    public AttrStats QueryAttrStats()
    {
        lock (_gate)
        {
            return Fingerprints.QueryAttrStats();
        }
    }

    public IReadOnlyDictionary<string, long> FoldDirectoryMtimes(CancellationToken ct)
    {
        lock (_gate)
        {
            return Fingerprints.FoldDirectoryMtimes(ct);
        }
    }

    public IReadOnlyList<(string Dir, long YoungestTicks, string Signals)> QueryOrphanDirs(
        int limit, int offset, out long total, string? nameContains = null,
        IReadOnlyList<string>? dirPrefixes = null)
    {
        lock (_gate)
        {
            return Fingerprints.QueryOrphanDirs(limit, offset, out total, nameContains, dirPrefixes);
        }
    }

    public void ReplaceOrphanDirs(IReadOnlyList<(string Dir, long YoungestTicks, string Signals)> rows)
    {
        lock (_gate)
        {
            Fingerprints.ReplaceOrphanDirs(rows);
        }
    }

    public void ReplaceDirStats(
        string scopeRoot, IReadOnlyList<DirStat> rows, int generation)
    {
        lock (_gate)
        {
            Fingerprints.ReplaceDirStats(scopeRoot, rows, generation);
        }
    }

    public IReadOnlyList<DirStat> QueryDirStats()
    {
        lock (_gate)
        {
            return Fingerprints.QueryDirStats();
        }
    }

    public void UpsertDeadLink(string path, string target)
    {
        lock (_gate)
        {
            Fingerprints.UpsertDeadLink(path, target);
        }
    }

    public void DeleteDeadLink(string path)
    {
        lock (_gate)
        {
            Fingerprints.DeleteDeadLink(path);
        }
    }

    public string? QueryDeadLink(string path)
    {
        lock (_gate)
        {
            return Fingerprints.QueryDeadLink(path);
        }
    }

    public IReadOnlyList<Fingerprint> QueryDuplicateMembers(string hash, int limit = 200)
    {
        lock (_gate)
        {
            return Fingerprints.QueryDuplicateMembers(hash, limit);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        try
        {
            EndBulk(commit: false); // Never leave a half-written run behind.
        }
        finally
        {
            try
            {
                Fingerprints.Dispose();
            }
            finally
            {
                Passport.Dispose();
            }
        }
    }
}
