using Microsoft.Data.Sqlite;

namespace Sentinel.Store;

// Durable investigation state: checkpoints, findings, and the tool
// audit trail. Lives in its OWN database file so checkpoint writes
// never join a scan's bulk transaction: cancelling or rolling back
// a scan must not erase the investigation checkpoint, and closing
// the app must leave resumable state behind.
// P2-01: durable budget state. EvidenceBytes maps the legacy
// EgressBytes column (renamed in code for accuracy; the column
// keeps its name so old databases migrate additively).
// EstimatedCostUsd null = unknown, stored as -1.0 under the
// legacy NOT NULL column (NaN is unbindable in
// Microsoft.Data.Sqlite; negative costs are impossible, so -1
// is unambiguous). The ONLY reader is ReadState below, pinned
// by test — no read site can mistake it for $0.00.
public sealed record InvestigationState(
    string Id,
    string ScanLabel,
    string Goal,
    string Status,
    string? StatusDetail,
    int EvidenceRevision,
    int CommittedGeneration,
    int ToolCalls,
    long EvidenceBytes,
    double ElapsedSeconds,
    long InputTokens,
    long OutputTokens,
    long ReasoningTokens,
    long CachedTokens,
    long TransmittedBytes,
    bool HasProviderUsage,
    double? EstimatedCostUsd,
    string UnresolvedJson,
    string UpdatedUtc,
    // A11: scope fingerprint the checkpoint was taken under (roots
    // + exclusions + excerpt policy). NULL = pre-A11 row whose
    // scope cannot be verified — never auto-resumed.
    string? ScopeFingerprint);

public sealed record AgentFindingRecord(
    string Id,
    string InvestigationId,
    int Revision,
    string Status,
    string Observation,
    string Interpretation,
    string EvidenceIdsJson,
    string Limitations,
    string SuggestedNext,
    string UpdatedUtc);

// P25: one durable opaque broker ID (f:/d:) minted during an
// investigation. Persisted so pre-restart evidence IDs stay
// resolvable after close/reopen; restored only under a matching
// scope fingerprint (Resume gates before importing).
public sealed record BrokerIdEntry(string Id, string Path);

public sealed class AgentStore : IDisposable
{
    private readonly SqliteConnection _conn;
    private readonly object _gate = new();
    private bool _disposed;

    public AgentStore(string dbPath)
    {
        var dir = Path.GetDirectoryName(dbPath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        _conn = new SqliteConnection($"Data Source={dbPath}");
        _conn.Open();
        EnsureSchema();
    }

    private void EnsureSchema()
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS AgentInvestigations(
                Id TEXT PRIMARY KEY,
                ScanLabel TEXT NOT NULL,
                Goal TEXT NOT NULL,
                Status TEXT NOT NULL,
                StatusDetail TEXT NULL,
                EvidenceRevision INTEGER NOT NULL DEFAULT 0,
                CommittedGeneration INTEGER NOT NULL DEFAULT 0,
                ToolCalls INTEGER NOT NULL DEFAULT 0,
                EgressBytes INTEGER NOT NULL DEFAULT 0,
                ElapsedSeconds REAL NOT NULL DEFAULT 0,
                InputTokens INTEGER NOT NULL DEFAULT 0,
                OutputTokens INTEGER NOT NULL DEFAULT 0,
                ReasoningTokens INTEGER NOT NULL DEFAULT 0,
                CachedTokens INTEGER NOT NULL DEFAULT 0,
                TransmittedBytes INTEGER NOT NULL DEFAULT 0,
                HasProviderUsage INTEGER NOT NULL DEFAULT 0,
                EstimatedCostUsd REAL NOT NULL DEFAULT 0,
                UnresolvedJson TEXT NOT NULL DEFAULT '[]',
                UpdatedUtc TEXT NOT NULL,
                ScopeFingerprint TEXT NULL);
            CREATE TABLE IF NOT EXISTS AgentFindings(
                Id TEXT PRIMARY KEY,
                InvestigationId TEXT NOT NULL,
                Revision INTEGER NOT NULL,
                Status TEXT NOT NULL,
                Observation TEXT NOT NULL,
                Interpretation TEXT NOT NULL,
                EvidenceIdsJson TEXT NOT NULL DEFAULT '[]',
                Limitations TEXT NOT NULL DEFAULT '',
                SuggestedNext TEXT NOT NULL DEFAULT '',
                UpdatedUtc TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS IX_AgentFindings_Inv
                ON AgentFindings(InvestigationId);
            CREATE TABLE IF NOT EXISTS AgentToolAudit(
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                InvestigationId TEXT NOT NULL,
                ToolName TEXT NOT NULL,
                Accepted INTEGER NOT NULL,
                Reason TEXT NULL,
                EgressBytes INTEGER NOT NULL DEFAULT 0,
                AtUtc TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS IX_AgentToolAudit_Inv
                ON AgentToolAudit(InvestigationId);
            CREATE TABLE IF NOT EXISTS AgentBrokerIds(
                InvestigationId TEXT NOT NULL,
                Id TEXT NOT NULL,
                Path TEXT NOT NULL,
                PRIMARY KEY (InvestigationId, Id));
            CREATE INDEX IF NOT EXISTS IX_AgentBrokerIds_Inv
                ON AgentBrokerIds(InvestigationId);
            """;
        cmd.ExecuteNonQuery();
        MigrateInvestigations();
    }

    // Additive migrations for databases created by earlier builds
    // (same pragma pattern as SentinelDb.MigrateScanRuns).
    private void MigrateInvestigations()
    {
        using var pragma = _conn.CreateCommand();
        pragma.CommandText = "SELECT name FROM pragma_table_info('AgentInvestigations');";
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (var reader = pragma.ExecuteReader())
        {
            while (reader.Read())
            {
                columns.Add(reader.GetString(0));
            }
        }

        string[] wanted =
        [
            "ElapsedSeconds REAL NOT NULL DEFAULT 0",
            "InputTokens INTEGER NOT NULL DEFAULT 0",
            "OutputTokens INTEGER NOT NULL DEFAULT 0",
            "ReasoningTokens INTEGER NOT NULL DEFAULT 0",
            "CachedTokens INTEGER NOT NULL DEFAULT 0",
            "TransmittedBytes INTEGER NOT NULL DEFAULT 0",
            "HasProviderUsage INTEGER NOT NULL DEFAULT 0",
            "ScopeFingerprint TEXT NULL",
        ];
        foreach (var def in wanted)
        {
            string name = def.Split(' ')[0];
            if (!columns.Contains(name))
            {
                using var alter = _conn.CreateCommand();
                alter.CommandText =
                    $"ALTER TABLE AgentInvestigations ADD COLUMN {def};";
                alter.ExecuteNonQuery();
            }
        }
    }

    public void UpsertInvestigation(
        string id,
        string scanLabel,
        string goal,
        string status,
        string? statusDetail,
        int evidenceRevision,
        int committedGeneration,
        int toolCalls,
        long evidenceBytes,
        double elapsedSeconds,
        long inputTokens,
        long outputTokens,
        long reasoningTokens,
        long cachedTokens,
        long transmittedBytes,
        bool hasProviderUsage,
        double? estimatedCostUsd,
        string unresolvedJson,
        string? scopeFingerprint = null)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO AgentInvestigations(Id, ScanLabel, Goal, Status, StatusDetail,
                    EvidenceRevision, CommittedGeneration, ToolCalls, EgressBytes,
                    ElapsedSeconds, InputTokens, OutputTokens, ReasoningTokens,
                    CachedTokens, TransmittedBytes, HasProviderUsage,
                    EstimatedCostUsd, UnresolvedJson, UpdatedUtc, ScopeFingerprint)
                VALUES ($id, $label, $goal, $status, $detail, $rev, $gen,
                    $calls, $bytes, $elapsed, $inTok, $outTok, $rsnTok,
                    $cchTok, $wire, $hasUse, $cost, $unresolved, $utc, $scopeFp)
                ON CONFLICT(Id) DO UPDATE SET
                    Status = excluded.Status,
                    StatusDetail = excluded.StatusDetail,
                    EvidenceRevision = excluded.EvidenceRevision,
                    CommittedGeneration = excluded.CommittedGeneration,
                    ToolCalls = excluded.ToolCalls,
                    EgressBytes = excluded.EgressBytes,
                    ElapsedSeconds = excluded.ElapsedSeconds,
                    InputTokens = excluded.InputTokens,
                    OutputTokens = excluded.OutputTokens,
                    ReasoningTokens = excluded.ReasoningTokens,
                    CachedTokens = excluded.CachedTokens,
                    TransmittedBytes = excluded.TransmittedBytes,
                    HasProviderUsage = excluded.HasProviderUsage,
                    EstimatedCostUsd = excluded.EstimatedCostUsd,
                    UnresolvedJson = excluded.UnresolvedJson,
                    -- A11: set-once. The first fingerprint wins; a
                    -- running investigation's scope never drifts.
                    ScopeFingerprint = COALESCE(AgentInvestigations.ScopeFingerprint, excluded.ScopeFingerprint),
                    UpdatedUtc = excluded.UpdatedUtc;
                """;
            cmd.Parameters.AddWithValue("$id", id);
            cmd.Parameters.AddWithValue("$label", scanLabel);
            cmd.Parameters.AddWithValue("$goal", goal);
            cmd.Parameters.AddWithValue("$status", status);
            cmd.Parameters.AddWithValue("$detail", (object?)statusDetail ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$rev", evidenceRevision);
            cmd.Parameters.AddWithValue("$gen", committedGeneration);
            cmd.Parameters.AddWithValue("$calls", toolCalls);
            cmd.Parameters.AddWithValue("$bytes", evidenceBytes);
            cmd.Parameters.AddWithValue("$elapsed", elapsedSeconds);
            cmd.Parameters.AddWithValue("$inTok", inputTokens);
            cmd.Parameters.AddWithValue("$outTok", outputTokens);
            cmd.Parameters.AddWithValue("$rsnTok", reasoningTokens);
            cmd.Parameters.AddWithValue("$cchTok", cachedTokens);
            cmd.Parameters.AddWithValue("$wire", transmittedBytes);
            cmd.Parameters.AddWithValue("$hasUse", hasProviderUsage ? 1 : 0);
            cmd.Parameters.AddWithValue(
                "$cost", estimatedCostUsd is null or < 0 ? -1.0 : estimatedCostUsd.Value);
            cmd.Parameters.AddWithValue("$unresolved", unresolvedJson);
            cmd.Parameters.AddWithValue("$utc", DateTime.UtcNow.ToString("O"));
            cmd.Parameters.AddWithValue("$scopeFp", (object?)scopeFingerprint ?? DBNull.Value);
            cmd.ExecuteNonQuery();
        }
    }

    public InvestigationState? GetInvestigation(string id)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                SELECT Id, ScanLabel, Goal, Status, StatusDetail, EvidenceRevision,
                       CommittedGeneration, ToolCalls, EgressBytes, ElapsedSeconds,
                       InputTokens, OutputTokens, ReasoningTokens, CachedTokens,
                       TransmittedBytes, HasProviderUsage, EstimatedCostUsd,
                       UnresolvedJson, UpdatedUtc, ScopeFingerprint
                FROM AgentInvestigations WHERE Id = $id;
                """;
            cmd.Parameters.AddWithValue("$id", id);
            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
            {
                return null;
            }

            return ReadState(reader);
        }
    }

    // Newest-first investigation history for the History page.
    public IReadOnlyList<InvestigationState> ListInvestigations(int limit = 50)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                SELECT Id, ScanLabel, Goal, Status, StatusDetail, EvidenceRevision,
                       CommittedGeneration, ToolCalls, EgressBytes, ElapsedSeconds,
                       InputTokens, OutputTokens, ReasoningTokens, CachedTokens,
                       TransmittedBytes, HasProviderUsage, EstimatedCostUsd,
                       UnresolvedJson, UpdatedUtc, ScopeFingerprint
                FROM AgentInvestigations ORDER BY UpdatedUtc DESC LIMIT $limit;
                """;
            cmd.Parameters.AddWithValue("$limit", Math.Max(1, limit));
            using var reader = cmd.ExecuteReader();
            var rows = new List<InvestigationState>();
            while (reader.Read())
            {
                rows.Add(ReadState(reader));
            }

            return rows;
        }
    }

    private static InvestigationState ReadState(SqliteDataReader reader)
    {
        double cost = reader.GetDouble(16);
        return new InvestigationState(
            reader.GetString(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.GetString(3),
            reader.IsDBNull(4) ? null : reader.GetString(4),
            reader.GetInt32(5),
            reader.GetInt32(6),
            reader.GetInt32(7),
            reader.GetInt64(8),
            reader.GetDouble(9),
            reader.GetInt64(10),
            reader.GetInt64(11),
            reader.GetInt64(12),
            reader.GetInt64(13),
            reader.GetInt64(14),
            reader.GetInt32(15) != 0,
            cost < 0 ? null : cost,
            reader.GetString(17),
            reader.GetString(18),
            reader.IsDBNull(19) ? null : reader.GetString(19));
    }

    public void UpsertFinding(
        string id,
        string investigationId,
        int revision,
        string status,
        string observation,
        string interpretation,
        string evidenceIdsJson,
        string limitations,
        string suggestedNext)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO AgentFindings(Id, InvestigationId, Revision, Status,
                    Observation, Interpretation, EvidenceIdsJson, Limitations,
                    SuggestedNext, UpdatedUtc)
                VALUES ($id, $inv, $rev, $status, $obs, $interp, $ev, $lim, $next, $utc)
                ON CONFLICT(Id) DO UPDATE SET
                    Revision = excluded.Revision,
                    Status = excluded.Status,
                    Observation = excluded.Observation,
                    Interpretation = excluded.Interpretation,
                    EvidenceIdsJson = excluded.EvidenceIdsJson,
                    Limitations = excluded.Limitations,
                    SuggestedNext = excluded.SuggestedNext,
                    UpdatedUtc = excluded.UpdatedUtc;
                """;
            cmd.Parameters.AddWithValue("$id", id);
            cmd.Parameters.AddWithValue("$inv", investigationId);
            cmd.Parameters.AddWithValue("$rev", revision);
            cmd.Parameters.AddWithValue("$status", status);
            cmd.Parameters.AddWithValue("$obs", observation);
            cmd.Parameters.AddWithValue("$interp", interpretation);
            cmd.Parameters.AddWithValue("$ev", evidenceIdsJson);
            cmd.Parameters.AddWithValue("$lim", limitations);
            cmd.Parameters.AddWithValue("$next", suggestedNext);
            cmd.Parameters.AddWithValue("$utc", DateTime.UtcNow.ToString("O"));
            cmd.ExecuteNonQuery();
        }
    }

    public IReadOnlyList<AgentFindingRecord> GetFindings(string investigationId)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                SELECT Id, InvestigationId, Revision, Status, Observation,
                       Interpretation, EvidenceIdsJson, Limitations,
                       SuggestedNext, UpdatedUtc
                FROM AgentFindings WHERE InvestigationId = $inv ORDER BY Id;
                """;
            cmd.Parameters.AddWithValue("$inv", investigationId);
            var rows = new List<AgentFindingRecord>();
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                rows.Add(new AgentFindingRecord(
                    reader.GetString(0),
                    reader.GetString(1),
                    reader.GetInt32(2),
                    reader.GetString(3),
                    reader.GetString(4),
                    reader.GetString(5),
                    reader.GetString(6),
                    reader.GetString(7),
                    reader.GetString(8),
                    reader.GetString(9)));
            }

            return rows;
        }
    }

    // P25: atomically replaces the durable opaque-ID map for one
    // investigation. Called before the finding that cites those IDs
    // persists, and on every checkpoint, so a crash can never leave
    // a finding citing IDs the map forgot.
    public void ReplaceBrokerIds(
        string investigationId, IReadOnlyList<BrokerIdEntry> rows)
    {
        lock (_gate)
        {
            using var begin = _conn.CreateCommand();
            begin.CommandText = "BEGIN IMMEDIATE;";
            begin.ExecuteNonQuery();
            try
            {
                using var del = _conn.CreateCommand();
                del.CommandText = "DELETE FROM AgentBrokerIds WHERE InvestigationId = $inv;";
                del.Parameters.AddWithValue("$inv", investigationId);
                del.ExecuteNonQuery();
                foreach (var row in rows)
                {
                    using var ins = _conn.CreateCommand();
                    ins.CommandText = """
                        INSERT INTO AgentBrokerIds(InvestigationId, Id, Path)
                        VALUES ($inv, $id, $path);
                        """;
                    ins.Parameters.AddWithValue("$inv", investigationId);
                    ins.Parameters.AddWithValue("$id", row.Id);
                    ins.Parameters.AddWithValue("$path", row.Path);
                    ins.ExecuteNonQuery();
                }

                using var commit = _conn.CreateCommand();
                commit.CommandText = "COMMIT;";
                commit.ExecuteNonQuery();
            }
            catch
            {
                using var rollback = _conn.CreateCommand();
                rollback.CommandText = "ROLLBACK;";
                rollback.ExecuteNonQuery();
                throw;
            }
        }
    }

    // P25: durable opaque-ID map in insertion order. Restored only
    // under a matching scope fingerprint (Resume gates first).
    public IReadOnlyList<BrokerIdEntry> GetBrokerIds(string investigationId)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                SELECT Id, Path FROM AgentBrokerIds
                WHERE InvestigationId = $inv ORDER BY rowid;
                """;
            cmd.Parameters.AddWithValue("$inv", investigationId);
            var rows = new List<BrokerIdEntry>();
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                rows.Add(new BrokerIdEntry(reader.GetString(0), reader.GetString(1)));
            }

            return rows;
        }
    }

    public void RecordToolAudit(
        string investigationId,
        string toolName,
        bool accepted,
        string? reason,
        long evidenceBytes)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO AgentToolAudit(InvestigationId, ToolName, Accepted,
                    Reason, EgressBytes, AtUtc)
                VALUES ($inv, $tool, $ok, $reason, $bytes, $utc);
                """;
            cmd.Parameters.AddWithValue("$inv", investigationId);
            cmd.Parameters.AddWithValue("$tool", toolName);
            cmd.Parameters.AddWithValue("$ok", accepted ? 1 : 0);
            cmd.Parameters.AddWithValue("$reason", (object?)reason ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$bytes", evidenceBytes);
            cmd.Parameters.AddWithValue("$utc", DateTime.UtcNow.ToString("O"));
            cmd.ExecuteNonQuery();
        }
    }

    public int CountToolAudits(string investigationId, bool? accepted = null)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = accepted is null
                ? "SELECT COUNT(*) FROM AgentToolAudit WHERE InvestigationId = $inv;"
                : "SELECT COUNT(*) FROM AgentToolAudit WHERE InvestigationId = $inv AND Accepted = $ok;";
            cmd.Parameters.AddWithValue("$inv", investigationId);
            if (accepted is not null)
            {
                cmd.Parameters.AddWithValue("$ok", accepted.Value ? 1 : 0);
            }

            return Convert.ToInt32(cmd.ExecuteScalar());
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _conn.Dispose();
    }
}
