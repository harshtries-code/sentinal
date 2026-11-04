using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Sentinel.Store;

// P26: the two-file layout. The legacy single file (sentinel.db)
// held rebuildable caches AND irreplaceable history together, so a
// corrupt cache took history down with it. The split is physical:
//   <stem>-passport.db      scan runs + crashes + devices + blocklist + keepers
//   <stem>-fingerprints.db  fingerprints + census + orphans + dead links + meta
// The agent store (sentinel-agent.db) is untouched: it was already
// its own file, and its tool-audit half belongs to E34.
// First open of a legacy file split-migrates it; the legacy file is
// renamed to a timestamped backup, never deleted. Derived files are
// disposable mid-migration (the legacy file is the source of truth
// until the final rename), so an interrupted migration restarts
// clean by deleting partial derived files first.
public static class StoreLayout
{
    public static string DerivePassportPath(string anchorPath) =>
        DeriveSibling(anchorPath, "-passport");

    public static string DeriveFingerprintPath(string anchorPath) =>
        DeriveSibling(anchorPath, "-fingerprints");

    // E32/E34: the vault manifest and the audit log are their own
    // files (05 §7: wiping one store never wipes the audit log).
    // The vault's quarantined BYTES live in the sibling directory.
    public static string DeriveVaultDbPath(string anchorPath) =>
        DeriveSibling(anchorPath, "-vault");

    public static string DeriveAuditDbPath(string anchorPath) =>
        DeriveSibling(anchorPath, "-audit");

    public static string DeriveVaultDir(string anchorPath)
    {
        string? dir = Path.GetDirectoryName(anchorPath);
        string stem = Path.GetFileNameWithoutExtension(anchorPath);
        string name = stem + "-vault";
        return string.IsNullOrEmpty(dir) ? name : Path.Combine(dir, name);
    }

    private static string DeriveSibling(string anchorPath, string suffix)
    {
        string? dir = Path.GetDirectoryName(anchorPath);
        string stem = Path.GetFileNameWithoutExtension(anchorPath);
        string ext = Path.GetExtension(anchorPath);
        if (string.IsNullOrEmpty(ext))
        {
            ext = ".db";
        }

        string name = stem + suffix + ext;
        return string.IsNullOrEmpty(dir) ? name : Path.Combine(dir, name);
    }

    // Idempotent: safe to call on every open/path access. Migrates a
    // legacy single file once, completes a stranded backup rename, and
    // otherwise returns immediately.
    public static void EnsureSplit(string anchorPath)
    {
        string passportPath = DerivePassportPath(anchorPath);
        bool legacyExists = File.Exists(anchorPath);
        bool passportExists = File.Exists(passportPath);
        if (!legacyExists || passportExists)
        {
            if (passportExists && legacyExists && LooksLikeLegacyStore(anchorPath))
            {
                // A previous migration copied everything but died
                // before the backup rename: complete it now.
                FinishBackupRename(anchorPath);
            }

            return;
        }

        // Legacy file, no passport yet: exclusive migration. The
        // mutex is per data-directory so unrelated stores (tests)
        // never serialize on each other.
        string mutexName = MutexNameFor(
            Path.GetDirectoryName(Path.GetFullPath(anchorPath)) ?? ".");
        using var mutex = new Mutex(false, mutexName);
        bool taken = false;
        try
        {
            try
            {
                taken = mutex.WaitOne(TimeSpan.FromSeconds(30));
            }
            catch (AbandonedMutexException)
            {
                taken = true;
            }

            if (!taken)
            {
                throw new InvalidOperationException(
                    "The local data store is busy (another Sentinel is migrating it).");
            }

            // Recheck under the lock: the winner may have finished.
            if (File.Exists(passportPath))
            {
                if (File.Exists(anchorPath) && LooksLikeLegacyStore(anchorPath))
                {
                    FinishBackupRename(anchorPath);
                }

                return;
            }

            if (!File.Exists(anchorPath))
            {
                return;
            }

            MigrateLegacy(anchorPath, passportPath);
        }
        finally
        {
            if (taken)
            {
                mutex.ReleaseMutex();
            }
        }
    }

    // Read-only legacy probe: true when the file opens AND carries
    // at least one legacy table. Garbage, foreign SQLite files, and
    // locked files answer false (the caller decides corrupt vs busy).
    public static bool LooksLikeLegacyStore(string anchorPath)
    {
        try
        {
            using var conn = new SqliteConnection(
                $"Data Source={anchorPath};Mode=ReadOnly;Pooling=false");
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT COUNT(*) FROM sqlite_master
                WHERE Type = 'table' AND Name IN ('ScanRuns', 'Fingerprints');
                """;
            return Convert.ToInt64(cmd.ExecuteScalar()) > 0;
        }
        catch
        {
            return false;
        }
    }

    private static void MigrateLegacy(string anchorPath, string passportPath)
    {
        string fingerprintPath = DeriveFingerprintPath(anchorPath);
        if (!LooksLikeLegacyStore(anchorPath))
        {
            throw new StoreMigrationException(
                "The legacy store at '" + anchorPath + "' is unreadable (not a Sentinel database or corrupt).");
        }

        // Partial derived files from an interrupted migration are
        // disposable: the legacy file is still the source of truth.
        DeleteIfPresent(passportPath);
        DeleteIfPresent(fingerprintPath);

        using (var passport = new PassportDb(passportPath))
        using (var fingerprints = new FingerprintDb(fingerprintPath))
        {
            CopyLegacyTables(anchorPath, passportPath, fingerprintPath);
        }

        FinishBackupRename(anchorPath);
    }

    private static void CopyLegacyTables(
        string anchorPath, string passportPath, string fingerprintPath)
    {
        // Copy through ATTACH with explicit column lists: legacy
        // files predate some columns (Status/Error/GapsCount/Mode on
        // runs; Tier/Regrowth/AttrFlags/ClassGen on fingerprints),
        // and the SELECT substitutes honest defaults for those.
        using var conn = new SqliteConnection($"Data Source={passportPath};Pooling=false");
        conn.Open();
        using var tx = conn.BeginTransaction();
        try
        {
            AttachLegacy(conn, tx, anchorPath, fingerprintPath);
            tx.Commit();
        }
        catch
        {
            tx.Rollback();
            throw;
        }
    }

    private static void AttachLegacy(
        SqliteConnection conn, SqliteTransaction tx, string anchorPath, string fingerprintPath)
    {
        using var attach = conn.CreateCommand();
        attach.Transaction = tx;
        attach.CommandText = "ATTACH $legacy AS legacy; ATTACH $fp AS fp;";
        attach.Parameters.AddWithValue("$legacy", anchorPath);
        attach.Parameters.AddWithValue("$fp", fingerprintPath);
        attach.ExecuteNonQuery();

        var legacyCols = LegacyColumns(conn, tx);
        CopyRuns(conn, tx, legacyCols);
        CopyTable(conn, tx, "fp", "Fingerprints",
            ["Path", "Size", "MTimeUtcTicks", "Hash", "LastSeenGeneration",
             "Tier", "Regrowth", "AttrFlags", "ClassGen"],
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Tier"] = "NULL",
                ["Regrowth"] = "NULL",
                ["AttrFlags"] = "0",
                ["ClassGen"] = "0",
            },
            legacyCols);
        CopyTable(conn, tx, "fp", "Meta",
            ["Key", "Value"],
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
            legacyCols);
        CopyTable(conn, tx, "fp", "OrphanDirs",
            ["Dir", "YoungestTicks", "Signals"],
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
            legacyCols);
        CopyTable(conn, tx, "fp", "DirStats",
            ["Dir", "DirectFiles", "DirectSubdirs", "DirectUnverified", "MtimeTicks", "Generation"],
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["DirectUnverified"] = "0",
            },
            legacyCols);
        CopyTable(conn, tx, "fp", "DeadLinks",
            ["Path", "Target"],
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
            legacyCols);
    }

    private static Dictionary<string, HashSet<string>> LegacyColumns(
        SqliteConnection conn, SqliteTransaction tx)
    {
        var tables = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (string table in new[]
            { "ScanRuns", "Fingerprints", "Meta", "OrphanDirs", "DirStats", "DeadLinks" })
        {
            var cols = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            // Two-arg form: the schema-qualified prefix form would
            // silently read MAIN's columns instead of legacy's.
            cmd.CommandText = $"SELECT name FROM pragma_table_info('{table}', 'legacy');";
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                cols.Add(reader.GetString(0));
            }

            tables[table] = cols;
        }

        return tables;
    }

    private static void CopyRuns(
        SqliteConnection conn, SqliteTransaction tx,
        Dictionary<string, HashSet<string>> legacyCols)
    {
        var cols = legacyCols["ScanRuns"];
        if (cols.Count == 0)
        {
            return;
        }

        // Pre-migration rows predate Running/Completed bookkeeping;
        // they came from finished scans, so Completed is honest.
        var select = new List<string>
        {
            "Id", "StartedUtc", "Root", "Generation",
            "FilesSeen", "BytesSeen", "FilesHashed", "DurationMs",
            cols.Contains("Status") ? "Status" : "'Completed'",
            cols.Contains("Error") ? "Error" : "NULL",
            cols.Contains("GapsCount") ? "GapsCount" : "0",
            cols.Contains("Mode") ? "Mode" : "'Unknown'",
        };
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText =
            "INSERT INTO main.ScanRuns(Id, StartedUtc, Root, Generation, " +
            "FilesSeen, BytesSeen, FilesHashed, DurationMs, " +
            "Status, Error, GapsCount, Mode) " +
            "SELECT " + string.Join(", ", select) + " FROM legacy.ScanRuns;";
        cmd.ExecuteNonQuery();
    }

    private static void CopyTable(
        SqliteConnection conn, SqliteTransaction tx, string schema, string table,
        IReadOnlyList<string> columns, IReadOnlyDictionary<string, string> defaults,
        Dictionary<string, HashSet<string>> legacyCols)
    {
        var have = legacyCols[table];
        if (have.Count == 0)
        {
            return;
        }

        var select = new List<string>();
        foreach (string col in columns)
        {
            if (have.Contains(col))
            {
                select.Add(col);
            }
            else if (defaults.TryGetValue(col, out string? fallback))
            {
                select.Add(fallback);
            }
            else
            {
                throw new StoreMigrationException(
                    $"Legacy table {table} lacks required column {col}.");
            }
        }

        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText =
            $"INSERT INTO {schema}.{table}({string.Join(", ", columns)}) " +
            $"SELECT {string.Join(", ", select)} FROM legacy.{table};";
        cmd.ExecuteNonQuery();
    }

    private static void FinishBackupRename(string anchorPath)
    {
        SqliteConnection.ClearAllPools();
        string? dir = Path.GetDirectoryName(anchorPath);
        if (string.IsNullOrEmpty(dir))
        {
            dir = ".";
        }

        string stem = Path.GetFileNameWithoutExtension(anchorPath);
        string ext = Path.GetExtension(anchorPath);
        if (string.IsNullOrEmpty(ext))
        {
            ext = ".db";
        }

        string stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
        int attempt = 0;
        string target;
        do
        {
            string suffix = attempt == 0 ? string.Empty : "-" + attempt;
            target = Path.Combine(dir, stem + "-legacy-" + stamp + suffix + ext);
            attempt++;
        }
        while (File.Exists(target));

        File.Move(anchorPath, target);
        // Sidecars belong to the legacy file; they ride along so the
        // backup set stays complete (and stop shadowing the name).
        MoveIfPresent(anchorPath + "-wal", target + "-wal");
        MoveIfPresent(anchorPath + "-shm", target + "-shm");
        MoveIfPresent(anchorPath + "-journal", target + "-journal");
    }

    private static void MoveIfPresent(string from, string to)
    {
        if (File.Exists(from))
        {
            File.Move(from, to);
        }
    }

    private static void DeleteIfPresent(string path)
    {
        try
        {
            File.Delete(path);
            File.Delete(path + "-wal");
            File.Delete(path + "-shm");
            File.Delete(path + "-journal");
        }
        catch
        {
            // Best effort: the open below reports a real failure.
        }
    }

    private static string MutexNameFor(string dir)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(
            Path.GetFullPath(dir).ToLowerInvariant()));
        return @"Local\SentinelStoreMigrate-" +
            Convert.ToHexString(hash).Substring(0, 16);
    }
}

// The legacy single file exists but cannot be split (unreadable or
// foreign). Callers route this to quarantine, never to silent
// deletion: the file may still hold user history.
public sealed class StoreMigrationException(string message) : InvalidOperationException(message);
