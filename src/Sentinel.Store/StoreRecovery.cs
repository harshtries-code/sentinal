using Microsoft.Data.Sqlite;

namespace Sentinel.Store;

// A08: cache recovery preserves history. Rebuilding the
// fingerprint cache never wipes run history, investigation
// checkpoints, or the agent store (the explicit full wipe is
// N63's separate contract), and corrupt files are quarantined,
// never deleted. A failed rebuild reports instead of clearing.
// P26: each file recovers independently — a corrupt cache
// quarantines while the Passport is untouched, and vice versa.
public enum RecoveryKind
{
    HistoryKept,
    QuarantinedAndRebuilt,
    Failed,
}

public sealed record RecoveryOutcome(
    bool Success,
    RecoveryKind Kind,
    string Detail,
    string? QuarantinePath);

public static class StoreRecovery
{
    public static RecoveryOutcome TryRebuildFingerprintCache(string anchorPath)
    {
        string? dir = Path.GetDirectoryName(anchorPath);
        if (string.IsNullOrEmpty(dir))
        {
            dir = ".";
        }

        try
        {
            Directory.CreateDirectory(dir);
        }
        catch (Exception ex)
        {
            return Fail("could not prepare the data folder (" + ex.Message + ").");
        }

        string passportPath = StoreLayout.DerivePassportPath(anchorPath);
        string fpPath = StoreLayout.DeriveFingerprintPath(anchorPath);
        bool legacyExists = File.Exists(anchorPath);
        bool passportExists = File.Exists(passportPath);

        // Legacy single file, never split: migrate-or-quarantine the
        // anchor itself (old contract, same messages).
        if (legacyExists && !passportExists)
        {
            return RebuildLegacyAnchor(anchorPath, dir);
        }

        // Complete a stranded backup rename from an interrupted
        // migration; never touches data files.
        if (legacyExists)
        {
            try
            {
                StoreLayout.EnsureSplit(anchorPath);
            }
            catch (Exception ex)
            {
                return Fail("could not finish the pending store migration (" + ex.Message + "). Nothing was deleted.");
            }
        }

        // Missing everything: nothing to preserve, just create fresh.
        if (!File.Exists(passportPath) && !File.Exists(fpPath))
        {
            try
            {
                using var fresh = new SentinelDb(anchorPath);
                return new RecoveryOutcome(
                    true,
                    RecoveryKind.HistoryKept,
                    "Fresh store created — nothing was stored yet.",
                    null);
            }
            catch (Exception ex)
            {
                return Fail("could not create a fresh store (" + ex.Message + ").");
            }
        }

        // Read-only probes first: a read-write open deletes a
        // stale -wal sidecar even when it throws, which would
        // destroy evidence before quarantine can preserve it.
        string? fpHealth = FingerprintDb.ProbeHealth(fpPath);
        string? ppHealth = PassportDb.ProbeHealth(passportPath);

        if (fpHealth is null)
        {
            // Healthy cache: clear it through SQL (works while
            // other handles are open) and keep every run row.
            // The cache file opens DIRECTLY: the Passport may be
            // corrupt, and that must not block the cache rebuild.
            try
            {
                using var cache = new FingerprintDb(fpPath);
                long cleared = cache.CountFingerprints();
                cache.ClearFingerprints();
                return new RecoveryOutcome(
                    true,
                    RecoveryKind.HistoryKept,
                    "Fingerprint cache rebuilt (" + cleared + " entries cleared), run history kept."
                        + PassportNote(passportPath, ppHealth),
                    null);
            }
            catch (Exception ex)
            {
                return Fail("could not clear the fingerprint cache (" + ex.Message + "). The store was left in place — nothing was deleted.");
            }
        }

        try
        {
            string kept = Quarantine(fpPath, dir);
            using var fresh = new FingerprintDb(fpPath);
            return new RecoveryOutcome(
                true,
                RecoveryKind.QuarantinedAndRebuilt,
                "Corrupt fingerprint cache moved to quarantine (" + kept + "); a fresh cache is ready and scans will re-discover everything."
                    + PassportNote(passportPath, ppHealth),
                kept);
        }
        catch (Exception ex)
        {
            return Fail("could not move the corrupt data aside (" + ex.Message + "). Nothing was deleted — retry after closing other programs.");
        }
    }

    // P26: Passport-side recovery. A corrupt Passport quarantines
    // into its own set and restarts fresh — the loss is stated
    // LOUDLY (runs, findings memory, crash trends, device history),
    // because unlike the cache this history cannot be rescanned.
    public static RecoveryOutcome TryRecoverPassport(string anchorPath)
    {
        string? dir = Path.GetDirectoryName(anchorPath);
        if (string.IsNullOrEmpty(dir))
        {
            dir = ".";
        }

        try
        {
            Directory.CreateDirectory(dir);
        }
        catch (Exception ex)
        {
            return Fail("could not prepare the data folder (" + ex.Message + ").");
        }

        string passportPath = StoreLayout.DerivePassportPath(anchorPath);
        bool legacyExists = File.Exists(anchorPath);
        bool passportExists = File.Exists(passportPath);

        if (legacyExists && !passportExists)
        {
            if (!StoreLayout.LooksLikeLegacyStore(anchorPath))
            {
                try
                {
                    string kept = Quarantine(anchorPath, dir);
                    using var fresh = new SentinelDb(anchorPath);
                    return new RecoveryOutcome(
                        true,
                        RecoveryKind.QuarantinedAndRebuilt,
                        "Unreadable legacy store moved to quarantine (" + kept + "); a fresh Passport starts now — past runs and history are NOT in the app anymore (files kept at " + kept + ").",
                        kept);
                }
                catch (Exception ex)
                {
                    return Fail("could not move the corrupt data aside (" + ex.Message + "). Nothing was deleted — retry after closing other programs.");
                }
            }

            try
            {
                using var store = new SentinelDb(anchorPath);
                int runs = store.ListRuns(int.MaxValue).Count;
                return new RecoveryOutcome(
                    true,
                    RecoveryKind.HistoryKept,
                    "Legacy store migrated; Passport history kept (" + runs + " runs).",
                    null);
            }
            catch (Exception ex)
            {
                return Fail("could not migrate the legacy store (" + ex.Message + "). Nothing was deleted.");
            }
        }

        if (!passportExists)
        {
            try
            {
                using var fresh = new PassportDb(passportPath);
                return new RecoveryOutcome(
                    true,
                    RecoveryKind.HistoryKept,
                    "Fresh Passport history created — nothing was stored yet.",
                    null);
            }
            catch (Exception ex)
            {
                return Fail("could not create a fresh Passport store (" + ex.Message + ").");
            }
        }

        string? health = PassportDb.ProbeHealth(passportPath);
        if (health is null)
        {
            int runs;
            try
            {
                using var passport = new PassportDb(passportPath);
                runs = passport.ListRuns(int.MaxValue).Count;
            }
            catch (Exception ex)
            {
                return Fail("could not read the Passport store (" + ex.Message + "). Nothing was deleted.");
            }

            return new RecoveryOutcome(
                true,
                RecoveryKind.HistoryKept,
                "Passport history verified healthy (" + runs + " runs); nothing rebuilt.",
                null);
        }

        try
        {
            string kept = Quarantine(passportPath, dir);
            using var fresh = new PassportDb(passportPath);
            return new RecoveryOutcome(
                true,
                RecoveryKind.QuarantinedAndRebuilt,
                "Corrupt Passport store moved to quarantine (" + kept + "); a fresh history starts now — past runs, crash trends, and device history are NOT in the app anymore (files kept at " + kept + ").",
                kept);
        }
        catch (Exception ex)
        {
            return Fail("could not move the corrupt data aside (" + ex.Message + "). Nothing was deleted — retry after closing other programs.");
        }
    }

    // Legacy anchor, never split: the pre-P26 contract. Readable
    // anchors migrate then clear; unreadable anchors quarantine.
    private static RecoveryOutcome RebuildLegacyAnchor(string anchorPath, string dir)
    {
        string? health = SentinelDb.ProbeHealth(anchorPath);
        if (health is null)
        {
            try
            {
                using var store = new SentinelDb(anchorPath);
                long cleared = store.CountFingerprints();
                store.ClearFingerprints();
                return new RecoveryOutcome(
                    true,
                    RecoveryKind.HistoryKept,
                    "Fingerprint cache rebuilt (" + cleared + " entries cleared), run history kept.",
                    null);
            }
            catch (Exception ex)
            {
                return Fail("could not clear the fingerprint cache (" + ex.Message + "). The store was left in place — nothing was deleted.");
            }
        }

        try
        {
            string kept = Quarantine(anchorPath, dir);
            using var fresh = new SentinelDb(anchorPath);
            return new RecoveryOutcome(
                true,
                RecoveryKind.QuarantinedAndRebuilt,
                "Corrupt store moved to quarantine (" + kept + "); a fresh store is ready and scans will re-discover everything.",
                kept);
        }
        catch (Exception ex)
        {
            return Fail("could not move the corrupt data aside (" + ex.Message + "). Nothing was deleted — retry after closing other programs.");
        }
    }

    // The Passport's state, appended to cache-rebuild notes so a
    // sick Passport never hides behind a successful cache rebuild.
    private static string PassportNote(string passportPath, string? ppHealth)
    {
        if (ppHealth is null)
        {
            int runs;
            try
            {
                using var passport = new PassportDb(passportPath);
                runs = passport.ListRuns(int.MaxValue).Count;
            }
            catch
            {
                return " The Passport history could not be read — recover it separately.";
            }

            return " Passport history kept (" + runs + " runs).";
        }

        return " WARNING: the Passport history store is corrupt (" + ppHealth + ") — recover it separately; history is at risk.";
    }

    private static RecoveryOutcome Fail(string detail) =>
        new(false, RecoveryKind.Failed, detail, null);

    // Moves the corrupt main file plus any SQLite sidecars
    // (-wal/-shm/-journal) into quarantine/ with a unique
    // timestamped name. Never deletes; never overwrites an older
    // quarantined set (interrupted rebuilds keep both).
    private static string Quarantine(string dbPath, string dir)
    {
        // Pooled handles from earlier opens of this file would
        // block the move; the store is corrupt, so pool warmth
        // is worthless here.
        SqliteConnection.ClearAllPools();
        string quarantine = Path.Combine(dir, "quarantine");
        Directory.CreateDirectory(quarantine);

        string stem = Path.GetFileName(dbPath);
        string stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
        int attempt = 0;
        string target;
        do
        {
            string suffix = attempt == 0 ? "" : "-" + attempt;
            target = Path.Combine(quarantine, stem + "-" + stamp + suffix);
            attempt++;
        }
        while (File.Exists(target));

        MoveIfPresent(dbPath, target);
        MoveIfPresent(dbPath + "-wal", target + "-wal");
        MoveIfPresent(dbPath + "-shm", target + "-shm");
        MoveIfPresent(dbPath + "-journal", target + "-journal");
        return target;
    }

    private static void MoveIfPresent(string from, string to)
    {
        if (File.Exists(from))
        {
            File.Move(from, to);
        }
    }
}
