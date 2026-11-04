using Sentinel.Engine.Policy;
using Sentinel.Store;

namespace Sentinel.Engine.Agent;

// Storage inspection tools (10 §3). All reads are scoped, bounded,
// and redacted. Arithmetic is exact and local; the model receives
// aggregates and bounded listings, never the drive.
public sealed class StorageTools
{
    public const int MaxRows = 200;
    private const int DirScanCap = 5000;

    private readonly EvidencePreviewHub _hub;
    private readonly SentinelDb? _db;

    public StorageTools(EvidencePreviewHub hub, SentinelDb? db = null)
    {
        _hub = hub;
        _db = db;
    }

    public IReadOnlyList<IInvestigationTool> All => new IInvestigationTool[]
    {
        new OverviewTool(_hub),
        new ListDirectoryTool(_hub),
        new QueryInventoryTool(_hub),
        new InspectFileTool(_hub, _db),
    };

    private sealed class OverviewTool : IInvestigationTool
    {
        private readonly EvidencePreviewHub _hub;

        public OverviewTool(EvidencePreviewHub hub)
        {
            _hub = hub;
        }

        public string Name => "get_scan_overview";

        public string Description =>
            "Coverage by scope: files/bytes observed, directories, gaps, " +
            "top directories by size, collection state. No raw file dump.";

        public string ParametersSchemaJson => """
            {"type":"object","properties":{},"additionalProperties":false}
            """;

        public ToolResult Execute(
            ToolBroker broker, InvestigationScope scope,
            IReadOnlyDictionary<string, string> args, CancellationToken ct)
        {
            var snap = _hub.Snapshot();
            long bytes = 0;
            foreach (var f in snap.Files)
            {
                bytes += f.Size;
            }

            var top = snap.Dirs
                .OrderByDescending(d => d.Bytes)
                .Take(10)
                .Select(d => new ToolResultItem(new Dictionary<string, string>
                {
                    ["dir_id"] = broker.MintDirId(d.Path),
                    ["path"] = SecretRedactor.RedactUserPrefix(d.Path),
                    ["files"] = d.Files.ToString(),
                    ["bytes"] = d.Bytes.ToString(),
                }))
                .ToList();

            var fields = new Dictionary<string, string>
            {
                ["revision"] = snap.Revision.ToString(),
                ["collection_complete"] = snap.IsComplete.ToString(),
                ["collection_aborted"] = snap.IsAborted.ToString(),
                ["preview_truncated"] = snap.Truncated.ToString(),
                ["files_observed"] = snap.Files.Count.ToString(),
                ["bytes_observed"] = bytes.ToString(),
                ["dirs_observed"] = snap.Dirs.Count.ToString(),
                ["gaps_observed"] = snap.Gaps.Count.ToString(),
                ["scope"] = string.Join(";", scope.Roots.Select(SecretRedactor.RedactUserPrefix)),
            };
            var head = new List<ToolResultItem> { new(fields) };
            head.AddRange(top);
            return new ToolResult(
                snap.ScanId, snap.Revision, DateTime.UtcNow, Name,
                ToolResultStatus.Ok, head,
                snap.Gaps.Take(20).Select(g => new ToolResultGap(
                    SecretRedactor.RedactUserPrefix(g.Path), g.Reason)).ToList(),
                snap.Truncated || snap.Gaps.Count > 20, null);
        }
    }

    private sealed class ListDirectoryTool : IInvestigationTool
    {
        private readonly EvidencePreviewHub _hub;

        public ListDirectoryTool(EvidencePreviewHub hub)
        {
            _hub = hub;
        }

        public string Name => "list_directory";

        public string Description =>
            "List children of dir_id (opaque ID only, never a path). " +
            "Args: dir_id (required), sort (name|size, default name), " +
            "limit 1-200 (default 50), cursor (paging). Discovers unflagged areas.";

        public string ParametersSchemaJson => """
            {"type":"object",
             "properties":{
               "dir_id":{"type":"string","description":"Opaque directory ID from an earlier result. Never a filesystem path."},
               "sort":{"type":"string","enum":["name","size"],"default":"name"},
               "limit":{"type":"integer","minimum":1,"maximum":200,"default":50},
               "cursor":{"type":"string","description":"Opaque paging cursor from a previous page."}},
             "required":["dir_id"],"additionalProperties":true}
            """;

        public ToolResult Execute(
            ToolBroker broker, InvestigationScope scope,
            IReadOnlyDictionary<string, string> args, CancellationToken ct)
        {
            if (!args.TryGetValue("dir_id", out var dirId))
            {
                throw new ToolRejectedException("Missing dir_id.");
            }

            string dir = broker.ResolveScopedPath(scope, dirId, "dir_id");
            if (!Directory.Exists(dir))
            {
                throw new ToolRejectedException($"NotADirectory '{dirId}'.");
            }

            int limit = ToolBroker.ParseBoundedInt(args, "limit", 50, 1, MaxRows);
            string sort = args.TryGetValue("sort", out var s) ? s : "name";
            string? cursor = args.TryGetValue("cursor", out var c) ? c : null;

            var entries = new List<(string Name, string Full, bool IsDir, long Size, long MTime)>();
            bool scanTruncated = false;
            int excludedSkipped = 0;
            try
            {
                foreach (var full in Directory.EnumerateFileSystemEntries(dir))
                {
                    ct.ThrowIfCancellationRequested();
                    // A11: excluded-from-inspection children are
                    // skipped BEFORE any stat — not named, not
                    // sized, not ID-minted. One summary gap keeps
                    // the pruning visible instead of silent.
                    if (scope.IsExcluded(full))
                    {
                        excludedSkipped++;
                        continue;
                    }

                    if (entries.Count >= DirScanCap)
                    {
                        scanTruncated = true;
                        break;
                    }

                    try
                    {
                        var attr = File.GetAttributes(full);
                        bool isDir = (attr & FileAttributes.Directory) != 0;
                        bool isLink = (attr & FileAttributes.ReparsePoint) != 0;
                        long size = 0;
                        long mtime = 0;
                        if (!isDir)
                        {
                            var info = new FileInfo(full);
                            size = info.Length;
                            mtime = info.LastWriteTimeUtc.Ticks;
                        }

                        string name = Path.GetFileName(full) + (isLink ? " [link]" : string.Empty);
                        entries.Add((name, full, isDir, size, mtime));
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        // P28: vendor-owned areas state WHY they are
                        // unreadable instead of a bare tag.
                        string tag = VendorProtected.IsVendorProtected(full)
                            ? " [unreadable:vendor-protected]"
                            : " [unreadable]";
                        entries.Add((Path.GetFileName(full) + tag, full, false, 0, 0));
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new ToolRejectedException("DirectoryUnreadable:" + ex.GetType().Name);
            }

            IEnumerable<(string Name, string Full, bool IsDir, long Size, long MTime)> ordered =
                sort == "size"
                    ? entries.OrderByDescending(e => e.Size).ThenBy(e => e.Name, StringComparer.Ordinal)
                    : entries.OrderBy(e => e.Name, StringComparer.Ordinal);
            if (cursor is not null)
            {
                ordered = ordered.SkipWhile(e =>
                    string.Compare(e.Name, cursor, StringComparison.Ordinal) <= 0);
            }

            var page = ordered.Take(limit + 1).ToList();
            bool hasMore = page.Count > limit;
            var items = new List<ToolResultItem>();
            foreach (var e in page.Take(limit))
            {
                items.Add(new ToolResultItem(new Dictionary<string, string>
                {
                    ["id"] = e.IsDir ? broker.MintDirId(e.Full) : broker.MintFileId(e.Full),
                    ["name"] = e.Name,
                    ["kind"] = e.IsDir ? "dir" : "file",
                    ["size"] = e.Size.ToString(),
                    ["mtime_utc_ticks"] = e.MTime.ToString(),
                }));
            }

            var snap = _hub.Snapshot();
            string? next = hasMore ? page[limit - 1].Name : null;
            var gaps = new List<ToolResultGap>();
            if (scanTruncated)
            {
                gaps.Add(new ToolResultGap(dirId, "DirScanCappedAt5000"));
            }

            if (excludedSkipped > 0)
            {
                gaps.Add(new ToolResultGap(dirId, $"ExcludedScopeSkipped:{excludedSkipped}"));
            }

            return new ToolResult(
                snap.ScanId, snap.Revision, DateTime.UtcNow, Name,
                ToolResultStatus.Ok, items, gaps,
                scanTruncated || hasMore, next);
        }
    }

    private sealed class QueryInventoryTool : IInvestigationTool
    {
        private readonly EvidencePreviewHub _hub;

        public QueryInventoryTool(EvidencePreviewHub hub)
        {
            _hub = hub;
        }

        public string Name => "query_inventory";

        public string Description =>
            "Typed filters over observed inventory (partial mid-scan; revision " +
            "stamped). Args: min_size, max_size, extension (.log), " +
            "name_contains, gap_only (true), sort (size|name), limit 1-200. " +
            "Group: group_by (extension|directory). No SQL, ever.";

        public string ParametersSchemaJson => """
            {"type":"object",
             "properties":{
               "min_size":{"type":"integer","minimum":0,"description":"Keep files at least this big, in bytes."},
               "max_size":{"type":"integer","minimum":0,"description":"Keep files at most this big, in bytes."},
               "extension":{"type":"string","description":"File extension with or without the dot, e.g. .log."},
               "name_contains":{"type":"string","description":"Case-insensitive substring of the file name."},
               "gap_only":{"type":"string","enum":["true","false"],"description":"\"true\" keeps only files with a collection gap."},
               "sort":{"type":"string","enum":["size","name"],"default":"size"},
               "limit":{"type":"integer","minimum":1,"maximum":200,"default":50},
               "group_by":{"type":"string","enum":["extension","directory"],"description":"Aggregate instead of listing rows."}},
             "required":[],"additionalProperties":true}
            """;

        public ToolResult Execute(
            ToolBroker broker, InvestigationScope scope,
            IReadOnlyDictionary<string, string> args, CancellationToken ct)
        {
            var snap = _hub.Snapshot();
            IEnumerable<PreviewFileEntry> q = snap.Files;

            if (args.TryGetValue("min_size", out var minRaw) && long.TryParse(minRaw, out long min))
            {
                q = q.Where(f => f.Size >= min);
            }

            if (args.TryGetValue("max_size", out var maxRaw) && long.TryParse(maxRaw, out long max))
            {
                q = q.Where(f => f.Size <= max);
            }

            if (args.TryGetValue("extension", out var ext) && !string.IsNullOrWhiteSpace(ext))
            {
                string want = ext.StartsWith('.') ? ext : "." + ext;
                q = q.Where(f => string.Equals(Path.GetExtension(f.Path), want, StringComparison.OrdinalIgnoreCase));
            }

            if (args.TryGetValue("name_contains", out var sub) && !string.IsNullOrWhiteSpace(sub))
            {
                q = q.Where(f => Path.GetFileName(f.Path).Contains(sub, StringComparison.OrdinalIgnoreCase));
            }

            if (args.TryGetValue("gap_only", out var gapRaw) && gapRaw == "true")
            {
                q = q.Where(f => f.GapReason is not null);
            }

            int limit = ToolBroker.ParseBoundedInt(args, "limit", 50, 1, MaxRows);
            string sort = args.TryGetValue("sort", out var s) ? s : "size";

            if (args.TryGetValue("group_by", out var group) && !string.IsNullOrWhiteSpace(group))
            {
                return Grouped(broker, snap, q, group, limit);
            }

            var ordered = sort == "name"
                ? q.OrderBy(f => f.Path, StringComparer.Ordinal)
                : q.OrderByDescending(f => f.Size).ThenBy(f => f.Path, StringComparer.Ordinal);
            var page = ordered.Take(limit + 1).ToList();
            bool hasMore = page.Count > limit;
            var items = page.Take(limit).Select(f => new ToolResultItem(
                new Dictionary<string, string>
                {
                    ["file_id"] = broker.MintFileId(f.Path),
                    ["path"] = SecretRedactor.RedactUserPrefix(f.Path),
                    ["size"] = f.Size.ToString(),
                    ["mtime_utc_ticks"] = f.MTimeUtcTicks.ToString(),
                    ["gap"] = f.GapReason ?? string.Empty,
                })).ToList();

            return new ToolResult(
                snap.ScanId, snap.Revision, DateTime.UtcNow, Name,
                ToolResultStatus.Ok, items, Array.Empty<ToolResultGap>(),
                snap.Truncated || hasMore, null);
        }

        private static ToolResult Grouped(
            ToolBroker broker, PreviewSnapshot snap,
            IEnumerable<PreviewFileEntry> q, string group, int limit)
        {
            IEnumerable<IGrouping<string, PreviewFileEntry>> groups = group switch
            {
                "extension" => q.GroupBy(f =>
                    Path.GetExtension(f.Path).ToLowerInvariant()),
                "directory" => q.GroupBy(f =>
                    Path.GetDirectoryName(f.Path) ?? string.Empty),
                _ => throw new ToolRejectedException($"Bad group_by '{group}'."),
            };

            var items = groups
                .Select(g => new ToolResultItem(new Dictionary<string, string>
                {
                    ["key"] = group == "directory"
                        ? SecretRedactor.RedactUserPrefix(g.Key)
                        : g.Key,
                    ["id"] = group == "directory" && !string.IsNullOrEmpty(g.Key)
                        ? broker.MintDirId(g.Key)
                        : string.Empty,
                    ["files"] = g.Count().ToString(),
                    ["bytes"] = g.Sum(f => f.Size).ToString(),
                }))
                .OrderByDescending(i => long.Parse(i.Fields["bytes"]))
                .Take(limit + 1)
                .ToList();
            bool hasMore = items.Count > limit;
            return new ToolResult(
                snap.ScanId, snap.Revision, DateTime.UtcNow, "query_inventory",
                ToolResultStatus.Ok, items.Take(limit).ToList(),
                Array.Empty<ToolResultGap>(), snap.Truncated || hasMore, null);
        }
    }

    private sealed class InspectFileTool : IInvestigationTool
    {
        private readonly EvidencePreviewHub _hub;
        private readonly SentinelDb? _db;

        public InspectFileTool(EvidencePreviewHub hub, SentinelDb? db)
        {
            _hub = hub;
            _db = db;
        }

        public string Name => "inspect_file";

        public string Description =>
            "Identity + attributes + hash state for file_id. Re-stats live; " +
            "reports stale when the file changed under the snapshot. " +
            "No execution, no content.";

        public string ParametersSchemaJson => """
            {"type":"object",
             "properties":{
               "file_id":{"type":"string","description":"Opaque file ID from an earlier result. Never a filesystem path."}},
             "required":["file_id"],"additionalProperties":true}
            """;

        public ToolResult Execute(
            ToolBroker broker, InvestigationScope scope,
            IReadOnlyDictionary<string, string> args, CancellationToken ct)
        {
            if (!args.TryGetValue("file_id", out var fileId))
            {
                throw new ToolRejectedException("Missing file_id.");
            }

            string path = broker.ResolveScopedPath(scope, fileId, "file_id");
            var snap = _hub.Snapshot();
            var seen = snap.Files.FirstOrDefault(f =>
                string.Equals(f.Path, path, StringComparison.OrdinalIgnoreCase));

            FileAttributes attr;
            long size;
            long mtime;
            try
            {
                attr = File.GetAttributes(path);
                if ((attr & FileAttributes.Directory) != 0)
                {
                    throw new ToolRejectedException($"NotAFile '{fileId}'.");
                }

                var info = new FileInfo(path);
                size = info.Length;
                mtime = info.LastWriteTimeUtc.Ticks;
            }
            catch (ToolRejectedException)
            {
                throw;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new ToolRejectedException("FileUnreadable:" + ex.GetType().Name);
            }

            bool stale = seen is not null
                && (seen.Size != size || seen.MTimeUtcTicks != mtime);
            string hashState = "missing";
            if (_db is not null)
            {
                try
                {
                    var fp = _db.GetFingerprint(path);
                    hashState = fp?.Hash is null ? "missing"
                        : fp.Size == size && fp.MTimeUtcTicks == mtime ? "verified" : "stale";
                }
                catch
                {
                    hashState = "unknown";
                }
            }

            var fields = new Dictionary<string, string>
            {
                ["file_id"] = fileId,
                ["path"] = SecretRedactor.RedactUserPrefix(path),
                ["size"] = size.ToString(),
                ["mtime_utc_ticks"] = mtime.ToString(),
                ["is_link"] = ((attr & FileAttributes.ReparsePoint) != 0).ToString(),
                ["is_placeholder"] = ((attr & FileAttributes.Offline) != 0).ToString(),
                ["hash_state"] = hashState,
                ["signer"] = "not-collected",
            };
            return new ToolResult(
                snap.ScanId, snap.Revision, DateTime.UtcNow, Name,
                stale ? ToolResultStatus.Stale : ToolResultStatus.Ok,
                [new ToolResultItem(fields)],
                Array.Empty<ToolResultGap>(), false, null);
        }
    }
}
