using Microsoft.Data.Sqlite;

namespace Sentinel.Store;

// One quarantined item's manifest row. VaultRelPath is relative to
// the item's per-volume directory under the vault root, so the whole
// vault can be relocated without rewriting the manifest.
public sealed record VaultItem(
    string Id,
    string BatchId,
    string OriginalPath,
    string VaultRelPath,
    string VolumeLabel,
    long SizeBytes,
    string Sha256,
    string MovedUtc,
    string TemplateId,
    string Actor,
    string Status,
    bool Verified,
    string? ReviewDueUtc,
    string? RestoredUtc,
    string? RestoredPath,
    string Detail);

// Item lifecycle. Quarantined and Restored are terminal-by-user;
// Interrupted* rows are crash residue awaiting ReconcileInterrupted;
// Superseded rows were re-decided by a later user-confirmed batch.
// There is NO deleted/purged status: the vault never deletes.
public static class VaultStatus
{
    public const string Quarantined = "Quarantined";
    public const string Restored = "Restored";
    public const string InterruptedMove = "InterruptedMove";
    public const string InterruptedRestore = "InterruptedRestore";
    public const string Superseded = "Superseded";
}

public sealed record VaultBatch(
    string IdempotencyKey,
    string BatchId,
    string TemplateId,
    string StartedUtc,
    string? FinishedUtc,
    string Status,
    string Note);

public sealed record RecoveryFinding(
    string ItemId,
    string OriginalPath,
    string Outcome,
    string Detail);

public sealed record RecoveryReport(
    IReadOnlyList<RecoveryFinding> Findings,
    int BookkeepingCompleted,
    int NeedsUserDecision,
    int BytesMissing);

// E32: the vault manifest. Every clean_items_to_vault move lands
// here BEFORE the filesystem move is considered done, and every
// restore lands here too. Crash-safe by construction: the executor
// writes InterruptedMove first, moves bytes, verifies, then flips to
// Quarantined — so any crash leaves rows ReconcileInterrupted can
// explain. Reconciliation only ever completes BOOKKEEPING; it never
// moves, deletes, or "finishes" a file mutation on its own.
public sealed class VaultStore : IDisposable
{
    public const int SchemaVersion = 1;

    private readonly SqliteConnection _conn;
    private readonly object _gate = new();
    private bool _disposed;

    public string DbPath { get; }

    public VaultStore(string dbPath)
    {
        DbPath = dbPath;
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
                CREATE TABLE IF NOT EXISTS VaultItems(
                  Id TEXT PRIMARY KEY,
                  BatchId TEXT NOT NULL,
                  OriginalPath TEXT NOT NULL,
                  VaultRelPath TEXT NOT NULL,
                  VolumeLabel TEXT NOT NULL,
                  SizeBytes INTEGER NOT NULL,
                  Sha256 TEXT NOT NULL,
                  MovedUtc TEXT NOT NULL,
                  TemplateId TEXT NOT NULL,
                  Actor TEXT NOT NULL,
                  Status TEXT NOT NULL,
                  Verified INTEGER NOT NULL,
                  ReviewDueUtc TEXT NULL,
                  RestoredUtc TEXT NULL,
                  RestoredPath TEXT NULL,
                  Detail TEXT NOT NULL DEFAULT '');
                CREATE INDEX IF NOT EXISTS IX_VaultItems_Batch ON VaultItems(BatchId);
                CREATE INDEX IF NOT EXISTS IX_VaultItems_Status ON VaultItems(Status);
                CREATE TABLE IF NOT EXISTS VaultOps(
                  IdempotencyKey TEXT PRIMARY KEY,
                  BatchId TEXT NOT NULL,
                  TemplateId TEXT NOT NULL,
                  StartedUtc TEXT NOT NULL,
                  FinishedUtc TEXT NULL,
                  Status TEXT NOT NULL,
                  Note TEXT NOT NULL DEFAULT '');
                PRAGMA user_version = 1;
                """;
            cmd.ExecuteNonQuery();
        }
    }

    // Starts a batch unless the idempotency key already ran. False =
    // duplicate: existingBatchId names the original run.
    public bool TryBeginBatch(
        string idempotencyKey, string batchId, string templateId,
        string startedUtc, out string? existingBatchId)
    {
        lock (_gate)
        {
            using var find = _conn.CreateCommand();
            find.CommandText = "SELECT BatchId FROM VaultOps WHERE IdempotencyKey = $key;";
            find.Parameters.AddWithValue("$key", idempotencyKey);
            object? hit = find.ExecuteScalar();
            if (hit is not null)
            {
                existingBatchId = Convert.ToString(hit);
                return false;
            }

            using var insert = _conn.CreateCommand();
            insert.CommandText = """
                INSERT INTO VaultOps(IdempotencyKey, BatchId, TemplateId, StartedUtc, Status)
                VALUES ($key, $batch, $template, $started, 'Running');
                """;
            insert.Parameters.AddWithValue("$key", idempotencyKey);
            insert.Parameters.AddWithValue("$batch", batchId);
            insert.Parameters.AddWithValue("$template", templateId);
            insert.Parameters.AddWithValue("$started", startedUtc);
            insert.ExecuteNonQuery();
            existingBatchId = null;
            return true;
        }
    }

    public void FinishBatch(string idempotencyKey, string status, string note, string finishedUtc)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                UPDATE VaultOps SET Status = $status, Note = $note, FinishedUtc = $finished
                WHERE IdempotencyKey = $key;
                """;
            cmd.Parameters.AddWithValue("$status", status);
            cmd.Parameters.AddWithValue("$note", note);
            cmd.Parameters.AddWithValue("$finished", finishedUtc);
            cmd.Parameters.AddWithValue("$key", idempotencyKey);
            cmd.ExecuteNonQuery();
        }
    }

    public VaultBatch? GetBatch(string idempotencyKey)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                SELECT IdempotencyKey, BatchId, TemplateId, StartedUtc, FinishedUtc, Status, Note
                FROM VaultOps WHERE IdempotencyKey = $key;
                """;
            cmd.Parameters.AddWithValue("$key", idempotencyKey);
            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
            {
                return null;
            }

            return new VaultBatch(
                reader.GetString(0), reader.GetString(1), reader.GetString(2),
                reader.GetString(3), reader.IsDBNull(4) ? null : reader.GetString(4),
                reader.GetString(5), reader.GetString(6));
        }
    }

    public void RecordItem(VaultItem item)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO VaultItems(Id, BatchId, OriginalPath, VaultRelPath, VolumeLabel,
                  SizeBytes, Sha256, MovedUtc, TemplateId, Actor, Status, Verified,
                  ReviewDueUtc, RestoredUtc, RestoredPath, Detail)
                VALUES ($id, $batch, $orig, $rel, $vol, $size, $sha, $moved,
                  $template, $actor, $status, $verified, $review, $restoredUtc, $restoredPath, $detail);
                """;
            cmd.Parameters.AddWithValue("$id", item.Id);
            cmd.Parameters.AddWithValue("$batch", item.BatchId);
            cmd.Parameters.AddWithValue("$orig", item.OriginalPath);
            cmd.Parameters.AddWithValue("$rel", item.VaultRelPath);
            cmd.Parameters.AddWithValue("$vol", item.VolumeLabel);
            cmd.Parameters.AddWithValue("$size", item.SizeBytes);
            cmd.Parameters.AddWithValue("$sha", item.Sha256);
            cmd.Parameters.AddWithValue("$moved", item.MovedUtc);
            cmd.Parameters.AddWithValue("$template", item.TemplateId);
            cmd.Parameters.AddWithValue("$actor", item.Actor);
            cmd.Parameters.AddWithValue("$status", item.Status);
            cmd.Parameters.AddWithValue("$verified", item.Verified ? 1 : 0);
            cmd.Parameters.AddWithValue("$review", (object?)item.ReviewDueUtc ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$restoredUtc", (object?)item.RestoredUtc ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$restoredPath", (object?)item.RestoredPath ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$detail", item.Detail);
            cmd.ExecuteNonQuery();
        }
    }

    public void MarkVerified(string id)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                UPDATE VaultItems SET Status = $quarantined, Verified = 1
                WHERE Id = $id;
                """;
            cmd.Parameters.AddWithValue("$quarantined", VaultStatus.Quarantined);
            cmd.Parameters.AddWithValue("$id", id);
            cmd.ExecuteNonQuery();
        }
    }

    public void MarkInterrupted(string id, string status, string detail)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = "UPDATE VaultItems SET Status = $status, Detail = $detail WHERE Id = $id;";
            cmd.Parameters.AddWithValue("$status", status);
            cmd.Parameters.AddWithValue("$detail", detail);
            cmd.Parameters.AddWithValue("$id", id);
            cmd.ExecuteNonQuery();
        }
    }

    public void MarkRestored(string id, string restoredUtc, string restoredPath, string detail)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                UPDATE VaultItems
                SET Status = $restored, RestoredUtc = $utc, RestoredPath = $path, Detail = $detail
                WHERE Id = $id;
                """;
            cmd.Parameters.AddWithValue("$restored", VaultStatus.Restored);
            cmd.Parameters.AddWithValue("$utc", restoredUtc);
            cmd.Parameters.AddWithValue("$path", restoredPath);
            cmd.Parameters.AddWithValue("$detail", detail);
            cmd.Parameters.AddWithValue("$id", id);
            cmd.ExecuteNonQuery();
        }
    }

    public void MarkSuperseded(string id, string detail)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = "UPDATE VaultItems SET Status = $status, Detail = $detail WHERE Id = $id;";
            cmd.Parameters.AddWithValue("$status", VaultStatus.Superseded);
            cmd.Parameters.AddWithValue("$detail", detail);
            cmd.Parameters.AddWithValue("$id", id);
            cmd.ExecuteNonQuery();
        }
    }

    public void SetReviewDue(string id, string? reviewDueUtc)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = "UPDATE VaultItems SET ReviewDueUtc = $due WHERE Id = $id;";
            cmd.Parameters.AddWithValue("$due", (object?)reviewDueUtc ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$id", id);
            cmd.ExecuteNonQuery();
        }
    }

    public VaultItem? Get(string id)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = SelectAll() + " WHERE Id = $id;";
            cmd.Parameters.AddWithValue("$id", id);
            using var reader = cmd.ExecuteReader();
            return reader.Read() ? ReadItem(reader) : null;
        }
    }

    // Restorable-now rows: quarantined AND hash-verified. Anything
    // else (interrupted, unverified, restored) is never offered as
    // one-click Undo — E33's gating rule reads this list.
    public IReadOnlyList<VaultItem> ListRestorable()
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = SelectAll() +
                " WHERE Status = $q AND Verified = 1 ORDER BY MovedUtc, Id;";
            cmd.Parameters.AddWithValue("$q", VaultStatus.Quarantined);
            using var reader = cmd.ExecuteReader();
            var rows = new List<VaultItem>();
            while (reader.Read())
            {
                rows.Add(ReadItem(reader));
            }

            return rows;
        }
    }

    // Everything the Vault page shows (quarantined, restored, and
    // residue states) — the user sees the vault's true contents.
    public IReadOnlyList<VaultItem> ListAll()
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = SelectAll() + " ORDER BY MovedUtc, Id;";
            using var reader = cmd.ExecuteReader();
            var rows = new List<VaultItem>();
            while (reader.Read())
            {
                rows.Add(ReadItem(reader));
            }

            return rows;
        }
    }

    public IReadOnlyList<VaultItem> ListByBatch(string batchId)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = SelectAll() + " WHERE BatchId = $batch ORDER BY Id;";
            cmd.Parameters.AddWithValue("$batch", batchId);
            using var reader = cmd.ExecuteReader();
            var rows = new List<VaultItem>();
            while (reader.Read())
            {
                rows.Add(ReadItem(reader));
            }

            return rows;
        }
    }

    public IReadOnlyList<VaultItem> FindInterrupted()
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = SelectAll() +
                " WHERE Status IN ($move, $restore) ORDER BY MovedUtc, Id;";
            cmd.Parameters.AddWithValue("$move", VaultStatus.InterruptedMove);
            cmd.Parameters.AddWithValue("$restore", VaultStatus.InterruptedRestore);
            using var reader = cmd.ExecuteReader();
            var rows = new List<VaultItem>();
            while (reader.Read())
            {
                rows.Add(ReadItem(reader));
            }

            return rows;
        }
    }

    // Retained bytes: verified quarantined rows only. Reported
    // SEPARATELY from free space (R13) — same-volume moves free
    // nothing, and this number never pretends otherwise.
    public long QueryRetainedBytes()
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                SELECT COALESCE(SUM(SizeBytes), 0) FROM VaultItems
                WHERE Status = $q AND Verified = 1;
                """;
            cmd.Parameters.AddWithValue("$q", VaultStatus.Quarantined);
            return Convert.ToInt64(cmd.ExecuteScalar());
        }
    }

    // Startup recovery. For every Interrupted* row, inspects BOTH
    // locations and each copy's hash, then completes ONLY the
    // bookkeeping that needs no user decision:
    //   - vault copy valid + source gone → row flips to
    //     Quarantined+Verified (the crash ate the flip; for a
    //     restore, the bytes verifiably never left the vault).
    //   - restore row + valid source + vault gone → row flips to
    //     Restored (the restore had finished on disk).
    //   - source still present (otherwise) → row UNCHANGED; the user
    //     re-decides with a fresh approval — recovery never
    //     completes a move or a restore by itself.
    //   - both copies gone/invalid → row UNCHANGED, reported as
    //     bytes-missing — data loss is reported, never papered over.
    // The caller MUST surface the report (E37 recovery banner).
    // This method performs no file mutation: reads + manifest writes.
    public RecoveryReport ReconcileInterrupted(
        string vaultRoot, Func<string, string?> hashReader, string observedUtc)
    {
        var findings = new List<RecoveryFinding>();
        int completed = 0;
        int needsDecision = 0;
        int missing = 0;

        foreach (var item in FindInterrupted())
        {
            string vaultPath = Path.Combine(vaultRoot, item.VolumeLabel, item.VaultRelPath);
            bool sourceExists = File.Exists(item.OriginalPath);
            bool vaultExists = File.Exists(vaultPath);
            string? vaultHash = vaultExists ? SafeHash(hashReader, vaultPath) : null;
            bool vaultValid = vaultHash is not null &&
                string.Equals(vaultHash, item.Sha256, StringComparison.OrdinalIgnoreCase);
            string? sourceHash = sourceExists ? SafeHash(hashReader, item.OriginalPath) : null;
            bool sourceValid = sourceHash is not null &&
                string.Equals(sourceHash, item.Sha256, StringComparison.OrdinalIgnoreCase);
            bool isRestore = string.Equals(
                item.Status, VaultStatus.InterruptedRestore, StringComparison.Ordinal);

            if (!sourceExists && vaultValid)
            {
                MarkVerified(item.Id);
                completed++;
                findings.Add(new RecoveryFinding(item.Id, item.OriginalPath,
                    "BookkeepingCompleted",
                    isRestore
                        ? "The restore had not started (bytes still verified in the vault); the record now matches the disk."
                        : "The move had finished before the interruption; the record now matches the disk."));
            }
            else if (isRestore && sourceValid && !vaultExists)
            {
                MarkRestored(item.Id, observedUtc, item.OriginalPath,
                    "The restore had finished before the interruption; the record now matches the disk.");
                completed++;
                findings.Add(new RecoveryFinding(item.Id, item.OriginalPath,
                    "BookkeepingCompleted",
                    "The restore had finished before the interruption; the record now matches the disk."));
            }
            else if (sourceExists)
            {
                needsDecision++;
                findings.Add(new RecoveryFinding(item.Id, item.OriginalPath,
                    "NeedsUserDecision",
                    vaultValid
                        ? "The original is still in place and a vault copy exists — re-confirm to finish, or leave it."
                        : "The original is still in place; the vault copy is incomplete — re-confirm to retry."));
            }
            else
            {
                missing++;
                findings.Add(new RecoveryFinding(item.Id, item.OriginalPath,
                    "BytesMissing",
                    vaultExists
                        ? "Neither a valid original nor a valid vault copy remains — the bytes cannot be recovered from the vault."
                        : "Both the original and the vault copy are gone — the bytes cannot be recovered from the vault."));
            }
        }

        return new RecoveryReport(findings, completed, needsDecision, missing);
    }

    private static string? SafeHash(Func<string, string?> hashReader, string path)
    {
        try
        {
            return hashReader(path);
        }
        catch
        {
            return null;
        }
    }

    private static string SelectAll() =>
        "SELECT Id, BatchId, OriginalPath, VaultRelPath, VolumeLabel, SizeBytes, Sha256, " +
        "MovedUtc, TemplateId, Actor, Status, Verified, ReviewDueUtc, RestoredUtc, RestoredPath, Detail " +
        "FROM VaultItems";

    private static VaultItem ReadItem(SqliteDataReader reader) => new(
        reader.GetString(0), reader.GetString(1), reader.GetString(2),
        reader.GetString(3), reader.GetString(4), reader.GetInt64(5),
        reader.GetString(6), reader.GetString(7), reader.GetString(8),
        reader.GetString(9), reader.GetString(10), reader.GetInt32(11) != 0,
        reader.IsDBNull(12) ? null : reader.GetString(12),
        reader.IsDBNull(13) ? null : reader.GetString(13),
        reader.IsDBNull(14) ? null : reader.GetString(14),
        reader.GetString(15));
}
