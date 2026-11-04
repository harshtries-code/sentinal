using Microsoft.Data.Sqlite;

namespace Sentinel.Store;

public sealed record CrashSnapshot(
    string Key,
    string EventUtc,
    string ObservedUtc,
    string Source,
    int EventId,
    string? Code,
    string? Module,
    string Bucket);

public sealed record CrashWeek(string WeekStartUtc, int Total);

public sealed record DeviceHistoryRow(
    long Id,
    string ObservedUtc,
    string InstanceId,
    string Name,
    int Problem,
    string Status,
    string? DriverVersion);

public sealed record BlockedDriver(
    string DeviceKey,
    string BadVersion,
    string Source,
    string Reason,
    string AddedUtc);

public sealed record KeeperDecision(
    string SetHash,
    string KeeperPath,
    string Rationale,
    string DecidedUtc);

// P27: one free-space sample per volume (C:, D:, ...). The panel
// renders first→last deltas as the free-space trend; 90-day
// retention keeps the table bounded (matches N61's compact horizon).
public sealed record DriveFreeSample(
    string Drive,
    string ObservedUtc,
    long FreeBytes,
    long TotalBytes);

// P26: the history half of the split. Irreplaceable rows live here:
// scan runs/coverage, crash snapshots, device history, the driver
// rollback blocklist, and duplicate keeper decisions. The schema is
// versioned (PRAGMA user_version); every migration runs inside one
// transaction WITH its version bump, so a crash between DDL and
// bump rolls back to the old version and the next open retries.
// DDL is idempotent (IF NOT EXISTS + column checks), so even a
// half-written schema converges on reopen instead of stranding.
public sealed class PassportDb : IDisposable
{
    public const int SchemaVersion = 3;

    private readonly SqliteConnection _conn;
    private readonly object _gate = new();
    private SqliteTransaction? _bulk;
    private bool _disposed;

    public string DbPath { get; }

    public PassportDb(string dbPath)
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
            // A08: a throwing constructor must not leak its open
            // handle — the abandoned lock blocked quarantine moves
            // and later opens of the same file. Pooling is on, so
            // Dispose alone parks the handle in the pool; clear it.
            _conn.Dispose();
            SqliteConnection.ClearAllPools();
            throw;
        }
    }

    private void EnsureSchema()
    {
        long version;
        using (var cmd = _conn.CreateCommand())
        {
            cmd.CommandText = "PRAGMA user_version;";
            version = (long)(cmd.ExecuteScalar() ?? 0L);
        }

        if (version > SchemaVersion)
        {
            throw new InvalidOperationException(
                $"Passport store schema v{version} is newer than this build (v{SchemaVersion}).");
        }

        if (version == SchemaVersion)
        {
            return;
        }

        using var tx = _conn.BeginTransaction();
        try
        {
            if (version < 1)
            {
                ApplyV1(tx);
            }

            if (version < 2)
            {
                ApplyV2(tx);
            }

            if (version < 3)
            {
                ApplyV3(tx);
            }

            using (var stamp = _conn.CreateCommand())
            {
                stamp.Transaction = tx;
                stamp.CommandText = $"PRAGMA user_version = {SchemaVersion};";
                stamp.ExecuteNonQuery();
            }

            tx.Commit();
        }
        catch
        {
            tx.Rollback();
            throw;
        }
    }

    private void ApplyV1(SqliteTransaction tx)
    {
        using var cmd = _conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS ScanRuns(
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                StartedUtc TEXT NOT NULL,
                Root TEXT NOT NULL,
                Generation INTEGER NOT NULL,
                FilesSeen INTEGER NOT NULL DEFAULT 0,
                BytesSeen INTEGER NOT NULL DEFAULT 0,
                FilesHashed INTEGER NOT NULL DEFAULT 0,
                DurationMs INTEGER NOT NULL DEFAULT 0,
                Status TEXT NOT NULL DEFAULT 'Running',
                Error TEXT NULL,
                GapsCount INTEGER NOT NULL DEFAULT 0,
                Mode TEXT NOT NULL DEFAULT 'Unknown');
            CREATE TABLE IF NOT EXISTS CrashSnapshots(
                Key TEXT PRIMARY KEY,
                EventUtc TEXT NOT NULL,
                ObservedUtc TEXT NOT NULL,
                Source TEXT NOT NULL,
                EventId INTEGER NOT NULL DEFAULT 0,
                Code TEXT NULL,
                Module TEXT NULL,
                Bucket TEXT NOT NULL DEFAULT '');
            CREATE INDEX IF NOT EXISTS IX_CrashSnapshots_EventUtc
                ON CrashSnapshots(EventUtc);
            CREATE TABLE IF NOT EXISTS DeviceHistory(
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                ObservedUtc TEXT NOT NULL,
                InstanceId TEXT NOT NULL,
                Name TEXT NOT NULL DEFAULT '',
                Problem INTEGER NOT NULL DEFAULT 0,
                Status TEXT NOT NULL DEFAULT '',
                DriverVersion TEXT NULL);
            CREATE INDEX IF NOT EXISTS IX_DeviceHistory_Device
                ON DeviceHistory(InstanceId, Id);
            CREATE TABLE IF NOT EXISTS DriverBlocklist(
                DeviceKey TEXT NOT NULL,
                BadVersion TEXT NOT NULL,
                Reason TEXT NOT NULL DEFAULT '',
                AddedUtc TEXT NOT NULL,
                PRIMARY KEY(DeviceKey, BadVersion));
            CREATE TABLE IF NOT EXISTS KeeperDecisions(
                SetHash TEXT PRIMARY KEY,
                KeeperPath TEXT NOT NULL,
                Rationale TEXT NOT NULL DEFAULT '',
                DecidedUtc TEXT NOT NULL);
            """;
        cmd.ExecuteNonQuery();
        MigrateScanRuns(tx);
    }

    // P27: additive drive-history table. Idempotent like the rest:
    // a v1 database gains the table on first open of the new build,
    // and the version stamp lands in the same transaction.
    private void ApplyV2(SqliteTransaction tx)
    {
        using var cmd = _conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS DriveSnapshots(
                Drive TEXT NOT NULL,
                ObservedUtc TEXT NOT NULL,
                FreeBytes INTEGER NOT NULL,
                TotalBytes INTEGER NOT NULL,
                PRIMARY KEY(Drive, ObservedUtc));
            CREATE INDEX IF NOT EXISTS IX_DriveSnapshots_Drive
                ON DriveSnapshots(Drive, ObservedUtc);
            """;
        cmd.ExecuteNonQuery();
    }

    // D42: the blocklist gains the ladder source, so keys match
    // the Source|Version form the driver matching consults.
    // Pre-D42 rows (written only by tests — no producer shipped
    // before D42) keep 'unknown' rather than a guessed source.
    private void ApplyV3(SqliteTransaction tx)
    {
        using var table = _conn.CreateCommand();
        table.Transaction = tx;
        table.CommandText = """
            SELECT COUNT(*) FROM sqlite_master
            WHERE type = 'table' AND name = 'DriverBlocklist';
            """;
        bool exists = Convert.ToInt64(table.ExecuteScalar()) > 0;
        if (!exists)
        {
            // Half-written v1 (only some tables exist): converge by
            // creating the full v3 shape directly.
            using var create = _conn.CreateCommand();
            create.Transaction = tx;
            create.CommandText = """
                CREATE TABLE DriverBlocklist(
                    DeviceKey TEXT NOT NULL,
                    BadVersion TEXT NOT NULL,
                    Source TEXT NOT NULL DEFAULT 'unknown',
                    Reason TEXT NOT NULL DEFAULT '',
                    AddedUtc TEXT NOT NULL,
                    PRIMARY KEY(DeviceKey, BadVersion));
                """;
            create.ExecuteNonQuery();
            return;
        }

        using var pragma = _conn.CreateCommand();
        pragma.Transaction = tx;
        pragma.CommandText = "SELECT name FROM pragma_table_info('DriverBlocklist');";
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (var reader = pragma.ExecuteReader())
        {
            while (reader.Read())
            {
                columns.Add(reader.GetString(0));
            }
        }

        if (!columns.Contains("Source"))
        {
            using var alter = _conn.CreateCommand();
            alter.Transaction = tx;
            alter.CommandText =
                "ALTER TABLE DriverBlocklist ADD COLUMN Source TEXT NOT NULL DEFAULT 'unknown';";
            alter.ExecuteNonQuery();
        }
    }

    // Additive migration for databases created by earlier builds
    // (moved verbatim from the single-file store).
    private void MigrateScanRuns(SqliteTransaction tx)
    {
        using var pragma = _conn.CreateCommand();
        pragma.Transaction = tx;
        pragma.CommandText = "SELECT name FROM pragma_table_info('ScanRuns');";
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (var reader = pragma.ExecuteReader())
        {
            while (reader.Read())
            {
                columns.Add(reader.GetString(0));
            }
        }

        if (!columns.Contains("Status"))
        {
            using var alter = _conn.CreateCommand();
            alter.Transaction = tx;
            alter.CommandText = "ALTER TABLE ScanRuns ADD COLUMN Status TEXT NOT NULL DEFAULT 'Running';";
            alter.ExecuteNonQuery();
        }

        if (!columns.Contains("Error"))
        {
            using var alter = _conn.CreateCommand();
            alter.Transaction = tx;
            alter.CommandText = "ALTER TABLE ScanRuns ADD COLUMN Error TEXT NULL;";
            alter.ExecuteNonQuery();
        }

        if (!columns.Contains("GapsCount"))
        {
            using var alter = _conn.CreateCommand();
            alter.Transaction = tx;
            alter.CommandText = "ALTER TABLE ScanRuns ADD COLUMN GapsCount INTEGER NOT NULL DEFAULT 0;";
            alter.ExecuteNonQuery();
        }

        if (!columns.Contains("Mode"))
        {
            using var alter = _conn.CreateCommand();
            alter.Transaction = tx;
            alter.CommandText = "ALTER TABLE ScanRuns ADD COLUMN Mode TEXT NOT NULL DEFAULT 'Unknown';";
            alter.ExecuteNonQuery();
        }
    }

    // A08: side-effect-free health probe. Opens read-only, so a
    // corrupt store is never mutated by the check itself. Returns
    // null when the store reads healthy, an explanation otherwise.
    // A missing file is "healthy" (nothing stored yet).
    public static string? ProbeHealth(string dbPath)
    {
        if (!File.Exists(dbPath))
        {
            return null;
        }

        try
        {
            using var conn = new SqliteConnection($"Data Source={dbPath};Mode=ReadOnly;Pooling=false");
            conn.Open();
            using var cmd = conn.CreateCommand();
            foreach (string table in new[]
                { "ScanRuns", "CrashSnapshots", "DeviceHistory", "DriverBlocklist", "KeeperDecisions" })
            {
                cmd.CommandText = $"SELECT COUNT(*) FROM {table};";
                cmd.ExecuteScalar();
            }

            return null;
        }
        catch (Exception ex)
        {
            return ex.GetType().Name + ": " + ex.Message.Split('\n')[0];
        }
    }

    // Bulk mode: the scan's passport half. The facade opens the
    // fingerprint bulk alongside this one and commits fingerprints
    // FIRST: orphan fingerprints (no run row) self-heal next
    // generation, while a run row without its fingerprints would
    // claim coverage the cache cannot show.
    public void BeginBulk()
    {
        lock (_gate)
        {
            _bulk ??= _conn.BeginTransaction();
        }
    }

    public void EndBulk(bool commit = true)
    {
        lock (_gate)
        {
            if (_bulk is null)
            {
                return;
            }

            try
            {
                if (commit)
                {
                    _bulk.Commit();
                }
                else
                {
                    _bulk.Rollback();
                }
            }
            finally
            {
                _bulk.Dispose();
                _bulk = null;
            }
        }
    }

    private void Enlist(SqliteCommand cmd)
    {
        cmd.Transaction = _bulk;
    }

    public int GetMaxGeneration()
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            Enlist(cmd);
            cmd.CommandText = "SELECT COALESCE(MAX(Generation), 0) FROM ScanRuns;";
            return Convert.ToInt32(cmd.ExecuteScalar());
        }
    }

    public long BeginRun(string root, int generation, string mode)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            Enlist(cmd);
            cmd.CommandText = """
                INSERT INTO ScanRuns(StartedUtc, Root, Generation, Status, Mode)
                VALUES ($utc, $root, $gen, 'Running', $mode);
                SELECT last_insert_rowid();
                """;
            cmd.Parameters.AddWithValue("$utc", DateTime.UtcNow.ToString("O"));
            cmd.Parameters.AddWithValue("$root", root);
            cmd.Parameters.AddWithValue("$gen", generation);
            cmd.Parameters.AddWithValue("$mode", mode);
            return (long)(cmd.ExecuteScalar() ?? 0L);
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
            using var cmd = _conn.CreateCommand();
            Enlist(cmd);
            cmd.CommandText = """
                UPDATE ScanRuns
                SET FilesSeen = $files, BytesSeen = $bytes,
                    FilesHashed = $hashed, DurationMs = $ms,
                    Status = $status, Error = $error, GapsCount = $gaps
                WHERE Id = $id;
                """;
            cmd.Parameters.AddWithValue("$files", filesSeen);
            cmd.Parameters.AddWithValue("$bytes", bytesSeen);
            cmd.Parameters.AddWithValue("$hashed", filesHashed);
            cmd.Parameters.AddWithValue("$ms", durationMs);
            cmd.Parameters.AddWithValue("$status", status);
            cmd.Parameters.AddWithValue("$error", (object?)error ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$gaps", Math.Max(0, gapsCount));
            cmd.Parameters.AddWithValue("$id", runId);
            cmd.ExecuteNonQuery();
        }
    }

    // Records an aborted run OUTSIDE any bulk transaction: the run row
    // must survive the rollback of its own partial fingerprints.
    // Callers record AFTER EndBulk(false), exactly as before.
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
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO ScanRuns(StartedUtc, Root, Generation, FilesSeen,
                    BytesSeen, FilesHashed, DurationMs, Status, Error, Mode)
                VALUES ($utc, $root, $gen, $files, $bytes, $hashed, $ms, $status, $error, $mode);
                SELECT last_insert_rowid();
                """;
            cmd.Parameters.AddWithValue("$utc", DateTime.UtcNow.ToString("O"));
            cmd.Parameters.AddWithValue("$root", root);
            cmd.Parameters.AddWithValue("$gen", generation);
            cmd.Parameters.AddWithValue("$mode", mode);
            cmd.Parameters.AddWithValue("$files", filesSeen);
            cmd.Parameters.AddWithValue("$bytes", bytesSeen);
            cmd.Parameters.AddWithValue("$hashed", filesHashed);
            cmd.Parameters.AddWithValue("$ms", durationMs);
            cmd.Parameters.AddWithValue("$status", status);
            cmd.Parameters.AddWithValue("$error", (object?)error ?? DBNull.Value);
            return (long)(cmd.ExecuteScalar() ?? 0L);
        }
    }

    public ScanRunInfo? GetRun(long runId)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            Enlist(cmd);
            cmd.CommandText = """
                SELECT Id, Generation, Root, Status, Error,
                       FilesSeen, BytesSeen, FilesHashed, DurationMs, GapsCount,
                       StartedUtc, Mode
                FROM ScanRuns WHERE Id = $id;
                """;
            cmd.Parameters.AddWithValue("$id", runId);
            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
            {
                return null;
            }

            return ReadRun(reader);
        }
    }

    // Newest-first run history for the History page (bounded).
    public IReadOnlyList<ScanRunInfo> ListRuns(int limit = 50)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            Enlist(cmd);
            cmd.CommandText = """
                SELECT Id, Generation, Root, Status, Error,
                       FilesSeen, BytesSeen, FilesHashed, DurationMs, GapsCount,
                       StartedUtc, Mode
                FROM ScanRuns ORDER BY Id DESC LIMIT $limit;
                """;
            cmd.Parameters.AddWithValue("$limit", Math.Max(1, limit));
            using var reader = cmd.ExecuteReader();
            var runs = new List<ScanRunInfo>();
            while (reader.Read())
            {
                runs.Add(ReadRun(reader));
            }

            return runs;
        }
    }

    private static ScanRunInfo ReadRun(SqliteDataReader reader) =>
        new(
            reader.GetInt64(0),
            reader.GetInt32(1),
            reader.GetString(2),
            reader.GetString(3),
            reader.IsDBNull(4) ? null : reader.GetString(4),
            reader.GetInt32(5),
            reader.GetInt64(6),
            reader.GetInt32(7),
            reader.GetInt64(8),
            reader.GetInt32(9),
            reader.GetString(10),
            reader.GetString(11));

    // Crash snapshots upsert by caller-built Key (source + record
    // identity), so re-collecting the same event overwrites one row
    // instead of appending forever. Callers pass bounded sets.
    public void RecordCrashSnapshots(IReadOnlyList<CrashSnapshot> rows)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            Enlist(cmd);
            using var tx = _bulk is null ? _conn.BeginTransaction() : null;
            if (tx is not null)
            {
                cmd.Transaction = tx;
            }

            cmd.CommandText = """
                INSERT INTO CrashSnapshots(Key, EventUtc, ObservedUtc, Source,
                    EventId, Code, Module, Bucket)
                VALUES ($key, $event, $observed, $source, $id, $code, $module, $bucket)
                ON CONFLICT(Key) DO UPDATE SET
                    EventUtc = excluded.EventUtc,
                    ObservedUtc = excluded.ObservedUtc,
                    Source = excluded.Source,
                    EventId = excluded.EventId,
                    Code = excluded.Code,
                    Module = excluded.Module,
                    Bucket = excluded.Bucket;
                """;
            var pKey = cmd.Parameters.Add("$key", SqliteType.Text);
            var pEvent = cmd.Parameters.Add("$event", SqliteType.Text);
            var pObserved = cmd.Parameters.Add("$observed", SqliteType.Text);
            var pSource = cmd.Parameters.Add("$source", SqliteType.Text);
            var pId = cmd.Parameters.Add("$id", SqliteType.Integer);
            var pCode = cmd.Parameters.Add("$code", SqliteType.Text);
            var pModule = cmd.Parameters.Add("$module", SqliteType.Text);
            var pBucket = cmd.Parameters.Add("$bucket", SqliteType.Text);
            foreach (var row in rows)
            {
                pKey.Value = row.Key;
                pEvent.Value = row.EventUtc;
                pObserved.Value = row.ObservedUtc;
                pSource.Value = row.Source;
                pId.Value = row.EventId;
                pCode.Value = (object?)row.Code ?? DBNull.Value;
                pModule.Value = (object?)row.Module ?? DBNull.Value;
                pBucket.Value = row.Bucket;
                cmd.ExecuteNonQuery();
            }

            tx?.Commit();
        }
    }

    // Weekly crash trend, oldest week first. Weeks count back from
    // utcNow; unparseable event stamps are skipped, never guessed.
    public IReadOnlyList<CrashWeek> QueryCrashTrend(int weeks, DateTime utcNow)
    {
        lock (_gate)
        {
            weeks = Math.Clamp(weeks, 1, 52);
            DateTime floor = utcNow.Date.AddDays(-7 * weeks);
            using var cmd = _conn.CreateCommand();
            Enlist(cmd);
            cmd.CommandText = """
                SELECT EventUtc FROM CrashSnapshots WHERE EventUtc >= $floor;
                """;
            cmd.Parameters.AddWithValue("$floor", floor.ToString("O"));
            var counts = new int[weeks];
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                if (!DateTime.TryParse(
                    reader.GetString(0), null,
                    System.Globalization.DateTimeStyles.RoundtripKind,
                    out DateTime when))
                {
                    continue;
                }

                int week = (int)(utcNow.Date - when.ToUniversalTime().Date).TotalDays / 7;
                if (week < 0 || week >= weeks)
                {
                    continue;
                }

                counts[weeks - 1 - week]++;
            }

            var result = new List<CrashWeek>(weeks);
            for (int i = 0; i < weeks; i++)
            {
                result.Add(new CrashWeek(
                    utcNow.Date.AddDays(-7 * (weeks - 1 - i)).ToString("O"),
                    counts[i]));
            }

            return result;
        }
    }

    public IReadOnlyList<CrashSnapshot> QueryCrashSnapshots(int limit = 200)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            Enlist(cmd);
            cmd.CommandText = """
                SELECT Key, EventUtc, ObservedUtc, Source, EventId, Code, Module, Bucket
                FROM CrashSnapshots ORDER BY EventUtc DESC LIMIT $limit;
                """;
            cmd.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 2000));
            using var reader = cmd.ExecuteReader();
            var rows = new List<CrashSnapshot>();
            while (reader.Read())
            {
                rows.Add(new CrashSnapshot(
                    reader.GetString(0), reader.GetString(1), reader.GetString(2),
                    reader.GetString(3), reader.GetInt32(4),
                    reader.IsDBNull(5) ? null : reader.GetString(5),
                    reader.IsDBNull(6) ? null : reader.GetString(6),
                    reader.GetString(7)));
            }

            return rows;
        }
    }

    // Device history appends ONLY on change (or first sighting): an
    // unchanged fleet re-collected daily costs zero rows. Returns the
    // number of rows appended.
    public int RecordDeviceStates(
        IReadOnlyList<(string InstanceId, string Name, int Problem, string Status, string? DriverVersion)> rows)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            Enlist(cmd);
            using var tx = _bulk is null ? _conn.BeginTransaction() : null;
            if (tx is not null)
            {
                cmd.Transaction = tx;
            }

            int added = 0;
            foreach (var row in rows)
            {
                cmd.CommandText = """
                    SELECT Problem, Status, DriverVersion FROM DeviceHistory
                    WHERE InstanceId = $id ORDER BY Id DESC LIMIT 1;
                    """;
                cmd.Parameters.Clear();
                cmd.Parameters.AddWithValue("$id", row.InstanceId);
                bool changed = true;
                using (var reader = cmd.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        int problem = reader.GetInt32(0);
                        string status = reader.GetString(1);
                        string? driver = reader.IsDBNull(2) ? null : reader.GetString(2);
                        changed = problem != row.Problem
                            || !string.Equals(status, row.Status, StringComparison.Ordinal)
                            || !string.Equals(driver, row.DriverVersion, StringComparison.Ordinal);
                    }
                }

                if (!changed)
                {
                    continue;
                }

                cmd.CommandText = """
                    INSERT INTO DeviceHistory(ObservedUtc, InstanceId, Name,
                        Problem, Status, DriverVersion)
                    VALUES ($utc, $id, $name, $problem, $status, $driver);
                    """;
                cmd.Parameters.Clear();
                cmd.Parameters.AddWithValue("$utc", DateTime.UtcNow.ToString("O"));
                cmd.Parameters.AddWithValue("$id", row.InstanceId);
                cmd.Parameters.AddWithValue("$name", row.Name);
                cmd.Parameters.AddWithValue("$problem", row.Problem);
                cmd.Parameters.AddWithValue("$status", row.Status);
                cmd.Parameters.AddWithValue("$driver", (object?)row.DriverVersion ?? DBNull.Value);
                cmd.ExecuteNonQuery();
                added++;
            }

            tx?.Commit();
            return added;
        }
    }

    public IReadOnlyList<DeviceHistoryRow> QueryDeviceHistory(string instanceId, int limit = 50)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            Enlist(cmd);
            cmd.CommandText = """
                SELECT Id, ObservedUtc, InstanceId, Name, Problem, Status, DriverVersion
                FROM DeviceHistory WHERE InstanceId = $id
                ORDER BY Id DESC LIMIT $limit;
                """;
            cmd.Parameters.AddWithValue("$id", instanceId);
            cmd.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 500));
            using var reader = cmd.ExecuteReader();
            var rows = new List<DeviceHistoryRow>();
            while (reader.Read())
            {
                rows.Add(new DeviceHistoryRow(
                    reader.GetInt64(0), reader.GetString(1), reader.GetString(2),
                    reader.GetString(3), reader.GetInt32(4), reader.GetString(5),
                    reader.IsDBNull(6) ? null : reader.GetString(6)));
            }

            return rows;
        }
    }

    // One row per known device: its latest state. Bounded.
    public IReadOnlyList<DeviceHistoryRow> QueryDeviceLatest(int limit = 500)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            Enlist(cmd);
            cmd.CommandText = """
                SELECT Id, ObservedUtc, InstanceId, Name, Problem, Status, DriverVersion
                FROM DeviceHistory AS h
                WHERE Id = (SELECT MAX(Id) FROM DeviceHistory WHERE InstanceId = h.InstanceId)
                ORDER BY InstanceId LIMIT $limit;
                """;
            cmd.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 2000));
            using var reader = cmd.ExecuteReader();
            var rows = new List<DeviceHistoryRow>();
            while (reader.Read())
            {
                rows.Add(new DeviceHistoryRow(
                    reader.GetInt64(0), reader.GetString(1), reader.GetString(2),
                    reader.GetString(3), reader.GetInt32(4), reader.GetString(5),
                    reader.IsDBNull(6) ? null : reader.GetString(6)));
            }

            return rows;
        }
    }

    // The rollback blocklist (01 §5.3: never repeat a bad one).
    // D42 producers (driver executors, via DriverBlocklist) record
    // the ladder source with every entry; the source is part of the
    // key the matching consults.
    public void AddBlockedDriver(string deviceKey, string badVersion, string source, string reason)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            Enlist(cmd);
            cmd.CommandText = """
                INSERT INTO DriverBlocklist(DeviceKey, BadVersion, Source, Reason, AddedUtc)
                VALUES ($device, $version, $source, $reason, $utc)
                ON CONFLICT(DeviceKey, BadVersion) DO UPDATE SET
                    Source = excluded.Source,
                    Reason = excluded.Reason, AddedUtc = excluded.AddedUtc;
                """;
            cmd.Parameters.AddWithValue("$device", deviceKey);
            cmd.Parameters.AddWithValue("$version", badVersion);
            cmd.Parameters.AddWithValue("$source", source);
            cmd.Parameters.AddWithValue("$reason", reason);
            cmd.Parameters.AddWithValue("$utc", DateTime.UtcNow.ToString("O"));
            cmd.ExecuteNonQuery();
        }
    }

    public bool IsBlockedDriver(string deviceKey, string version)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            Enlist(cmd);
            cmd.CommandText = """
                SELECT COUNT(*) FROM DriverBlocklist
                WHERE DeviceKey = $device AND BadVersion = $version;
                """;
            cmd.Parameters.AddWithValue("$device", deviceKey);
            cmd.Parameters.AddWithValue("$version", version);
            return Convert.ToInt64(cmd.ExecuteScalar()) > 0;
        }
    }

    public IReadOnlyList<BlockedDriver> QueryBlockedDrivers(int limit = 200)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            Enlist(cmd);
            cmd.CommandText = """
                SELECT DeviceKey, BadVersion, Source, Reason, AddedUtc
                FROM DriverBlocklist ORDER BY AddedUtc DESC LIMIT $limit;
                """;
            cmd.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 1000));
            using var reader = cmd.ExecuteReader();
            var rows = new List<BlockedDriver>();
            while (reader.Read())
            {
                rows.Add(new BlockedDriver(
                    reader.GetString(0), reader.GetString(1), reader.GetString(2),
                    reader.GetString(3), reader.GetString(4)));
            }

            return rows;
        }
    }

    // Operator unblock: removing a key is itself an audited app
    // action — the store just deletes. Returns false when the key
    // was not present.
    public bool RemoveBlockedDriver(string deviceKey, string badVersion)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            Enlist(cmd);
            cmd.CommandText = """
                DELETE FROM DriverBlocklist
                WHERE DeviceKey = $device AND BadVersion = $version;
                """;
            cmd.Parameters.AddWithValue("$device", deviceKey);
            cmd.Parameters.AddWithValue("$version", badVersion);
            return cmd.ExecuteNonQuery() > 0;
        }
    }

    // Duplicate "real one" verdicts: one remembered keeper per exact
    // set hash, overwritten when a later scan reasons differently.
    public void RecordKeeperDecision(string setHash, string keeperPath, string rationale)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            Enlist(cmd);
            cmd.CommandText = """
                INSERT INTO KeeperDecisions(SetHash, KeeperPath, Rationale, DecidedUtc)
                VALUES ($hash, $keeper, $rationale, $utc)
                ON CONFLICT(SetHash) DO UPDATE SET
                    KeeperPath = excluded.KeeperPath,
                    Rationale = excluded.Rationale,
                    DecidedUtc = excluded.DecidedUtc;
                """;
            cmd.Parameters.AddWithValue("$hash", setHash);
            cmd.Parameters.AddWithValue("$keeper", keeperPath);
            cmd.Parameters.AddWithValue("$rationale", rationale);
            cmd.Parameters.AddWithValue("$utc", DateTime.UtcNow.ToString("O"));
            cmd.ExecuteNonQuery();
        }
    }

    public KeeperDecision? QueryKeeperDecision(string setHash)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            Enlist(cmd);
            cmd.CommandText = """
                SELECT SetHash, KeeperPath, Rationale, DecidedUtc
                FROM KeeperDecisions WHERE SetHash = $hash;
                """;
            cmd.Parameters.AddWithValue("$hash", setHash);
            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
            {
                return null;
            }

            return new KeeperDecision(
                reader.GetString(0), reader.GetString(1),
                reader.GetString(2), reader.GetString(3));
        }
    }

    // P27: records one free-space sample; samples older than 90
    // days for the same drive are pruned in the same call so the
    // table cannot grow without bound. Drive keys are normalized
    // ("c:" -> "C:") so one drive keeps one history.
    public void RecordDriveSample(string drive, DateTime observedUtc, long freeBytes, long totalBytes)
    {
        string key = (drive ?? string.Empty).Trim().ToUpperInvariant();
        if (key.Length == 0)
        {
            return;
        }

        string observed = observedUtc.ToUniversalTime().ToString("O");
        string floor = observedUtc.ToUniversalTime().AddDays(-90).ToString("O");
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            Enlist(cmd);
            cmd.CommandText = """
                INSERT INTO DriveSnapshots(Drive, ObservedUtc, FreeBytes, TotalBytes)
                VALUES ($drive, $utc, $free, $total)
                ON CONFLICT(Drive, ObservedUtc) DO UPDATE SET
                    FreeBytes = excluded.FreeBytes, TotalBytes = excluded.TotalBytes;
                DELETE FROM DriveSnapshots WHERE Drive = $drive AND ObservedUtc < $floor;
                """;
            cmd.Parameters.AddWithValue("$drive", key);
            cmd.Parameters.AddWithValue("$utc", observed);
            cmd.Parameters.AddWithValue("$free", freeBytes);
            cmd.Parameters.AddWithValue("$total", totalBytes);
            cmd.Parameters.AddWithValue("$floor", floor);
            cmd.ExecuteNonQuery();
        }
    }

    // P27: newest-first samples for one drive since a floor (or all
    // when floor is null), bounded. The panel diffs first vs last.
    public IReadOnlyList<DriveFreeSample> QueryDriveTrend(string drive, DateTime? sinceUtc = null, int limit = 90)
    {
        string key = (drive ?? string.Empty).Trim().ToUpperInvariant();
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            Enlist(cmd);
            cmd.CommandText = sinceUtc is null
                ? "SELECT Drive, ObservedUtc, FreeBytes, TotalBytes FROM DriveSnapshots "
                    + "WHERE Drive = $drive ORDER BY ObservedUtc DESC LIMIT $limit;"
                : "SELECT Drive, ObservedUtc, FreeBytes, TotalBytes FROM DriveSnapshots "
                    + "WHERE Drive = $drive AND ObservedUtc >= $floor ORDER BY ObservedUtc DESC LIMIT $limit;";
            cmd.Parameters.AddWithValue("$drive", key);
            if (sinceUtc is not null)
            {
                cmd.Parameters.AddWithValue("$floor", sinceUtc.Value.ToUniversalTime().ToString("O"));
            }

            cmd.Parameters.AddWithValue("$limit", Math.Clamp(limit, 1, 500));
            using var reader = cmd.ExecuteReader();
            var rows = new List<DriveFreeSample>();
            while (reader.Read())
            {
                rows.Add(new DriveFreeSample(
                    reader.GetString(0), reader.GetString(1),
                    reader.GetInt64(2), reader.GetInt64(3)));
            }

            return rows;
        }
    }

    // P27: drives with any history, for the trend renderer.
    public IReadOnlyList<string> QueryDriveKeys()
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            Enlist(cmd);
            cmd.CommandText = "SELECT DISTINCT Drive FROM DriveSnapshots ORDER BY Drive;";
            using var reader = cmd.ExecuteReader();
            var rows = new List<string>();
            while (reader.Read())
            {
                rows.Add(reader.GetString(0));
            }

            return rows;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        EndBulk(commit: false); // Never leave a half-written run behind.
        _conn.Dispose();
    }
}
