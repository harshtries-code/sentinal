using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Sentinel.Store;

// One audit entry (05 §8 minimum fields + chain links). FindingIds
// rides as parsed JSON text — the store never interprets it.
public sealed record AuditEntry(
    long Seq,
    string Utc,
    string Actor,
    string ActionId,
    string FindingIdsJson,
    string? EvidenceHash,
    string BeforeJson,
    string AfterJson,
    string BackupRef,
    string UndoState,
    string AppVersion,
    string ModelId,
    string PackVersion,
    string PrevHash,
    string EntryHash);

public sealed record AuditIntegrity(
    bool Ok,
    long? BrokenAtSeq,
    string Detail);

public sealed record SealResult(
    bool Archived,
    string? ArchivePath,
    string? ArchiveHash,
    int EntriesSealed,
    string Detail);

// E34: the append-only, hash-chained action audit log (05 §8–8.1).
// Each entry stores hash(previous entry + this entry); the History
// page verifies the chain and shows integrity OK/BROKEN. There is no
// update or delete API — the only row removal in existence is Seal,
// which first writes the full archive, and Seal itself is recorded.
// Signing is SPECIFIED BUT DEFERRED: archives carry an explicit
// "unsigned" marker and no signature claim is made anywhere.
public sealed class ActionAuditLog : IDisposable
{
    public const int SchemaVersion = 1;

    // 05 §8.1: seal threshold.
    public const long SealThresholdBytes = 50L * 1024 * 1024;

    public const string GenesisHash = "GENESIS:v1";

    private readonly SqliteConnection _conn;
    private readonly object _gate = new();
    private readonly string _appVersion;
    private readonly string _modelId;
    private readonly string _packVersion;
    private bool _disposed;

    public string DbPath { get; }

    public ActionAuditLog(string dbPath, string appVersion, string modelId, string packVersion)
    {
        DbPath = dbPath;
        _appVersion = appVersion;
        _modelId = modelId;
        _packVersion = packVersion;
        string? dir = Path.GetDirectoryName(dbPath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        _conn = new SqliteConnection($"Data Source={dbPath}");
        try
        {
            _conn.Open();
            using (var busy = _conn.CreateCommand())
            {
                busy.CommandText = "PRAGMA busy_timeout = 5000;";
                busy.ExecuteNonQuery();
            }

            EnsureSchema();
        }
        catch
        {
            _conn.Dispose();
            SqliteConnection.ClearAllPools();
            throw;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
        }

        _conn.Dispose();
    }

    private void EnsureSchema()
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE IF NOT EXISTS AuditEntries(
                  Seq INTEGER PRIMARY KEY AUTOINCREMENT,
                  Utc TEXT NOT NULL,
                  Actor TEXT NOT NULL,
                  ActionId TEXT NOT NULL,
                  FindingIdsJson TEXT NOT NULL,
                  EvidenceHash TEXT NULL,
                  BeforeJson TEXT NOT NULL,
                  AfterJson TEXT NOT NULL,
                  BackupRef TEXT NOT NULL,
                  UndoState TEXT NOT NULL,
                  AppVersion TEXT NOT NULL,
                  ModelId TEXT NOT NULL,
                  PackVersion TEXT NOT NULL,
                  PrevHash TEXT NOT NULL,
                  EntryHash TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS IX_Audit_Action ON AuditEntries(ActionId);
                CREATE TABLE IF NOT EXISTS SealState(
                  Id INTEGER PRIMARY KEY CHECK (Id = 1),
                  LastArchiveHash TEXT NOT NULL,
                  LastArchiveUtc TEXT NOT NULL,
                  SealedThroughSeq INTEGER NOT NULL,
                  SealedEntries INTEGER NOT NULL);
                PRAGMA user_version = 1;
                """;
            cmd.ExecuteNonQuery();
        }
    }

    // Appends one entry and returns its sequence number. Versions are
    // stamped from construction wiring, never from the caller.
    public long Append(
        string utc, string actor, string actionId, string findingIdsJson,
        string? evidenceHash, string beforeJson, string afterJson,
        string backupRef, string undoState, string detail)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            string prev = CurrentTipHash();
            using var cmd = _conn.CreateCommand();
            // The detail rides inside AfterJson-adjacent storage? No:
            // detail is part of the hashed body via its own column.
            cmd.CommandText = """
                INSERT INTO AuditEntries(Utc, Actor, ActionId, FindingIdsJson, EvidenceHash,
                  BeforeJson, AfterJson, BackupRef, UndoState, AppVersion, ModelId, PackVersion,
                  PrevHash, EntryHash)
                VALUES ($utc, $actor, $action, $findings, $evidence, $before, $after,
                  $backup, $undo, $app, $model, $pack, $prev, $hash);
                SELECT last_insert_rowid();
                """;
            // Seq is assigned by the insert, so the hash covers the
            // previous tip + the full body; the seq itself is bound by
            // the contiguity check in VerifyChain.
            string hash = ComputeHash(prev, utc, actor, actionId, findingIdsJson,
                evidenceHash ?? string.Empty, beforeJson, AfterWithDetail(afterJson, detail),
                backupRef, undoState, _appVersion, _modelId, _packVersion);
            cmd.Parameters.AddWithValue("$utc", utc);
            cmd.Parameters.AddWithValue("$actor", actor);
            cmd.Parameters.AddWithValue("$action", actionId);
            cmd.Parameters.AddWithValue("$findings", findingIdsJson);
            cmd.Parameters.AddWithValue("$evidence", (object?)evidenceHash ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$before", beforeJson);
            cmd.Parameters.AddWithValue("$after", AfterWithDetail(afterJson, detail));
            cmd.Parameters.AddWithValue("$backup", backupRef);
            cmd.Parameters.AddWithValue("$undo", undoState);
            cmd.Parameters.AddWithValue("$app", _appVersion);
            cmd.Parameters.AddWithValue("$model", _modelId);
            cmd.Parameters.AddWithValue("$pack", _packVersion);
            cmd.Parameters.AddWithValue("$prev", prev);
            cmd.Parameters.AddWithValue("$hash", hash);
            object? id = cmd.ExecuteScalar();
            return Convert.ToInt64(id);
        }
    }

    // The human sentence is stored as the AfterJson prefix
    // ("detail\nafter-json") so it is hashed WITH the entry instead
    // of riding alongside unprotected. Readers split on the first \n.
    private static string AfterWithDetail(string afterJson, string detail) =>
        detail + "\n" + afterJson;

    public static (string Detail, string AfterJson) SplitAfter(string stored)
    {
        int cut = stored.IndexOf('\n');
        return cut < 0 ? (stored, string.Empty) : (stored.Substring(0, cut), stored.Substring(cut + 1));
    }

    public AuditIntegrity VerifyChain()
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            return VerifyChainCore(ReadAllOrdered());
        }
    }

    // 05 §8.1 rotation: writes the FULL archive, hashes it, deletes
    // the rows, and records the link for the next chain — all inside
    // one transaction, so a crash keeps the old chain intact. The
    // archive is explicitly UNSIGNED (signing deferred, no claim).
    public SealResult Seal(string archivePath, string observedUtc)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            var rows = ReadAllOrdered();
            if (rows.Count == 0)
            {
                return new SealResult(false, null, null, 0, "Nothing to seal — the log is empty.");
            }

            var integrity = VerifyChainCore(rows);
            if (!integrity.Ok)
            {
                return new SealResult(false, null, null, 0,
                    "Refusing to seal a BROKEN chain (" + integrity.Detail + "). Repair first.");
            }

            string? dir = Path.GetDirectoryName(archivePath);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }

            string json = AuditExport.BuildSealArchive(rows, observedUtc, _appVersion);
            string temp = archivePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
            File.WriteAllText(temp, json, Encoding.UTF8);
            string archiveHash;
            using (var stream = File.Open(temp, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                archiveHash = Convert.ToHexString(SHA256.HashData(stream));
            }

            File.Move(temp, archivePath, overwrite: true);

            using var tx = _conn.BeginTransaction();
            try
            {
                using (var del = _conn.CreateCommand())
                {
                    del.Transaction = tx;
                    del.CommandText = "DELETE FROM AuditEntries;";
                    del.ExecuteNonQuery();
                }

                using (var seal = _conn.CreateCommand())
                {
                    seal.Transaction = tx;
                    seal.CommandText = """
                        INSERT INTO SealState(Id, LastArchiveHash, LastArchiveUtc, SealedThroughSeq, SealedEntries)
                        VALUES (1, $hash, $utc, $through, $count)
                        ON CONFLICT(Id) DO UPDATE SET LastArchiveHash = $hash, LastArchiveUtc = $utc,
                          SealedThroughSeq = $through, SealedEntries = SealState.SealedEntries + $count;
                        """;
                    seal.Parameters.AddWithValue("$hash", archiveHash);
                    seal.Parameters.AddWithValue("$utc", observedUtc);
                    seal.Parameters.AddWithValue("$through", rows[^1].Seq);
                    seal.Parameters.AddWithValue("$count", rows.Count);
                    seal.ExecuteNonQuery();
                }

                tx.Commit();
            }
            catch
            {
                tx.Rollback();
                throw;
            }

            return new SealResult(true, archivePath, archiveHash, rows.Count,
                $"Sealed {rows.Count} entr(ies) to '{archivePath}' (unsigned archive; signing deferred).");
        }
    }

    public long Count()
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM AuditEntries;";
            return Convert.ToInt64(cmd.ExecuteScalar());
        }
    }

    public long SizeBytes()
    {
        try
        {
            var info = new FileInfo(DbPath);
            return info.Exists ? info.Length : 0;
        }
        catch
        {
            return 0;
        }
    }

    public bool NeedsSeal() => SizeBytes() > SealThresholdBytes;

    public IReadOnlyList<AuditEntry> ListRecent(int limit)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = SelectAll() + " ORDER BY Seq DESC LIMIT $n;";
            cmd.Parameters.AddWithValue("$n", Math.Max(1, limit));
            using var reader = cmd.ExecuteReader();
            var rows = new List<AuditEntry>();
            while (reader.Read())
            {
                rows.Add(ReadEntry(reader));
            }

            return rows;
        }
    }

    public IReadOnlyList<AuditEntry> ListByAction(string actionId, int limit = 500)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = SelectAll() + " WHERE ActionId = $action ORDER BY Seq DESC LIMIT $n;";
            cmd.Parameters.AddWithValue("$action", actionId);
            cmd.Parameters.AddWithValue("$n", Math.Max(1, limit));
            using var reader = cmd.ExecuteReader();
            var rows = new List<AuditEntry>();
            while (reader.Read())
            {
                rows.Add(ReadEntry(reader));
            }

            return rows;
        }
    }

    private AuditIntegrity VerifyChainCore(List<AuditEntry> rows)
    {
        var seal = ReadSeal();
        long expectSeq = seal?.SealedThroughSeq + 1 ?? 1;
        string expectPrev = seal?.LastArchiveHash ?? GenesisHash;
        if (rows.Count == 0)
        {
            return new AuditIntegrity(true, null, "Empty log — nothing to verify.");
        }

        string prev = expectPrev;
        foreach (var row in rows)
        {
            if (row.Seq != expectSeq)
            {
                return new AuditIntegrity(false, row.Seq,
                    $"Gap: expected seq {expectSeq} but found {row.Seq} — entries were deleted.");
            }

            if (!string.Equals(row.PrevHash, prev, StringComparison.Ordinal))
            {
                return new AuditIntegrity(false, row.Seq,
                    $"Link break at seq {row.Seq}: PrevHash does not match seq {row.Seq - 1}'s hash.");
            }

            string recomputed = ComputeHash(row.PrevHash, row.Utc, row.Actor, row.ActionId,
                row.FindingIdsJson, row.EvidenceHash ?? string.Empty, row.BeforeJson,
                row.AfterJson, row.BackupRef, row.UndoState,
                row.AppVersion, row.ModelId, row.PackVersion);
            if (!string.Equals(recomputed, row.EntryHash, StringComparison.OrdinalIgnoreCase))
            {
                return new AuditIntegrity(false, row.Seq,
                    $"Hash mismatch at seq {row.Seq}: the entry was modified after writing.");
            }

            prev = row.EntryHash;
            expectSeq++;
        }

        return new AuditIntegrity(true, null,
            $"OK: {rows.Count} entr(ies) verified, tip seq {rows[^1].Seq}.");
    }

    private string CurrentTipHash()
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "SELECT EntryHash FROM AuditEntries ORDER BY Seq DESC LIMIT 1;";
        object? tip = cmd.ExecuteScalar();
        if (tip is not null)
        {
            return Convert.ToString(tip) ?? GenesisHash;
        }

        var seal = ReadSeal();
        return seal?.LastArchiveHash ?? GenesisHash;
    }

    private sealed record SealRow(string LastArchiveHash, string LastArchiveUtc, long SealedThroughSeq);

    private SealRow? ReadSeal()
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "SELECT LastArchiveHash, LastArchiveUtc, SealedThroughSeq FROM SealState WHERE Id = 1;";
        using var reader = cmd.ExecuteReader();
        return reader.Read()
            ? new SealRow(reader.GetString(0), reader.GetString(1), reader.GetInt64(2))
            : null;
    }

    private List<AuditEntry> ReadAllOrdered()
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = SelectAll() + " ORDER BY Seq;";
        using var reader = cmd.ExecuteReader();
        var rows = new List<AuditEntry>();
        while (reader.Read())
        {
            rows.Add(ReadEntry(reader));
        }

        return rows;
    }

    private static string SelectAll() =>
        "SELECT Seq, Utc, Actor, ActionId, FindingIdsJson, EvidenceHash, BeforeJson, AfterJson, " +
        "BackupRef, UndoState, AppVersion, ModelId, PackVersion, PrevHash, EntryHash FROM AuditEntries";

    private static AuditEntry ReadEntry(SqliteDataReader reader) => new(
        reader.GetInt64(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
        reader.GetString(4), reader.IsDBNull(5) ? null : reader.GetString(5),
        reader.GetString(6), reader.GetString(7), reader.GetString(8), reader.GetString(9),
        reader.GetString(10), reader.GetString(11), reader.GetString(12),
        reader.GetString(13), reader.GetString(14));

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(ActionAuditLog));
        }
    }

    internal static string ComputeHash(
        string prevHash, string utc, string actor, string actionId, string findingIdsJson,
        string evidenceHash, string beforeJson, string afterJson, string backupRef,
        string undoState, string appVersion, string modelId, string packVersion)
    {
        string body = string.Join("\n", new[]
        {
            prevHash, utc, actor, actionId, findingIdsJson, evidenceHash,
            beforeJson, afterJson, backupRef, undoState, appVersion, modelId, packVersion,
        });
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body)));
    }
}
