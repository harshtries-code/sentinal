using System.Text;

namespace Sentinel.Engine.Agent;

// Class F excerpts (05 §7.1). This is the ONLY path by which file
// text reaches the cloud. Approved evidence types only, bounded
// windows, secret-redacted at the boundary, truncation always
// stated. Everything else returns a coverage limitation — and
// returning text here IS sending content off-device, logged as such.
public sealed class ExcerptTools : IInvestigationTool
{
    public const int MaxLines = 200;
    public const int MaxBytes = 64 * 1024;

    // A11: bump whenever the 05 §7.1 approved/never type lists
    // change. The version is part of the scope fingerprint, so a
    // privacy-policy change invalidates resumed investigations
    // whose excerpts were taken under older rules.
    public const int PolicyVersion = 1;

    private static readonly HashSet<string> ApprovedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".log", ".ini", ".cfg", ".conf", ".json", ".xml",
        ".yaml", ".yml", ".ps1", ".bat", ".cmd", ".vbs", ".js",
    };

    private static readonly HashSet<string> DeniedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".docx", ".doc", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx",
        ".exe", ".dll", ".sys", ".drv", ".dat", ".db", ".sqlite",
        ".sqlite3", ".evtx", ".dmp", ".mdmp", ".zip", ".7z", ".rar",
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".mp4", ".mp3",
    };

    private static readonly string[] DeniedNameMarkers =
    [
        "login data", "cookies", "key4.db", "logins.json", "ntuser.dat",
        "sam", "system", "security", ".pem", ".pfx", ".p12", "id_rsa",
    ];

    private readonly EvidencePreviewHub _hub;

    public ExcerptTools(EvidencePreviewHub hub)
    {
        _hub = hub;
    }

    public string Name => "read_text_excerpt";

    public string Description =>
        "Bounded redacted text window for approved diagnostic types " +
        "(logs, configs, scripts under investigation). Args: file_id " +
        "(required), max_lines 1-200, max_bytes up to 64KiB. Anything " +
        "else is a coverage limitation, never sent.";

    public string ParametersSchemaJson => """
        {"type":"object",
         "properties":{
           "file_id":{"type":"string","description":"Opaque file ID from an earlier result. Never a filesystem path."},
           "max_lines":{"type":"integer","minimum":1,"maximum":200,"default":200},
           "max_bytes":{"type":"integer","minimum":1,"maximum":65536,"default":65536}},
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

        // A11: identity re-stat, mirroring inspect_file. When the
        // hub saw this file and the live size/mtime no longer
        // match, the excerpt would mix generations — go stale and
        // send nothing. Files the hub never saw (live listings)
        // have no generation to contradict.
        var seen = snap.Files.FirstOrDefault(f =>
            string.Equals(f.Path, path, StringComparison.OrdinalIgnoreCase));
        if (seen is not null)
        {
            long liveSize;
            long liveMtime;
            try
            {
                var live = new FileInfo(path);
                liveSize = live.Length;
                liveMtime = live.LastWriteTimeUtc.Ticks;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new ToolRejectedException("FileUnreadable:" + ex.GetType().Name);
            }

            if (seen.Size != liveSize || seen.MTimeUtcTicks != liveMtime)
            {
                return new ToolResult(
                    snap.ScanId, snap.Revision, DateTime.UtcNow, Name,
                    ToolResultStatus.Stale,
                    Array.Empty<ToolResultItem>(),
                    [new ToolResultGap(fileId, "ChangedUnderSnapshot")], false, null);
            }
        }

        string? denial = ClassifyDenied(scope, path);
        if (denial is not null)
        {
            return new ToolResult(
                snap.ScanId, snap.Revision, DateTime.UtcNow, Name,
                ToolResultStatus.Denied,
                Array.Empty<ToolResultItem>(),
                [new ToolResultGap(fileId, denial)], false, null);
        }

        int maxLines = ToolBroker.ParseBoundedInt(args, "max_lines", MaxLines, 1, MaxLines);
        int maxBytes = ToolBroker.ParseBoundedInt(args, "max_bytes", MaxBytes, 1, MaxBytes);

        byte[] raw;
        long totalBytes;
        try
        {
            var info = new FileInfo(path);
            totalBytes = info.Length;
            using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 81920, useAsync: false);
            var buf = new byte[maxBytes + 1];
            int read = 0;
            int n;
            while (read < buf.Length
                && (n = stream.Read(buf, read, buf.Length - read)) > 0)
            {
                ct.ThrowIfCancellationRequested();
                read += n;
            }

            raw = buf.AsSpan(0, read).ToArray();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ToolRejectedException("FileUnreadable:" + ex.GetType().Name);
        }

        bool byteTruncated = raw.Length > maxBytes;
        if (byteTruncated)
        {
            raw = raw.AsSpan(0, maxBytes).ToArray();
        }

        ToolResult DeniedNotText() => new(
            snap.ScanId, snap.Revision, DateTime.UtcNow, Name,
            ToolResultStatus.Denied,
            Array.Empty<ToolResultItem>(),
            [new ToolResultGap(fileId, "NotText")], false, null);

        // BOM-recognized UTF-16 (P2-02) decodes past the BOM and is
        // judged as TEXT — ordinary UTF-16 is full of NUL bytes.
        // A decoded NUL still means binary (fail closed). No-BOM
        // content keeps the raw NUL guard, then UTF-8 decode.
        string encoding = DetectEncoding(raw);
        string text;
        if (encoding is "utf-16le" or "utf-16be")
        {
            var enc = encoding == "utf-16le"
                ? Encoding.Unicode
                : Encoding.BigEndianUnicode;
            text = enc.GetString(raw, 2, raw.Length - 2);
            if (text.Contains('\0'))
            {
                return DeniedNotText();
            }
        }
        else
        {
            if (raw.AsSpan().IndexOf((byte)0) >= 0)
            {
                return DeniedNotText();
            }

            text = Encoding.UTF8.GetString(raw);
        }

        var lines = text.Split('\n');
        bool lineTruncated = lines.Length > maxLines;
        if (lineTruncated)
        {
            text = string.Join('\n', lines.Take(maxLines));
        }

        text = SecretRedactor.RedactSecrets(text);
        text = SecretRedactor.RedactUserPrefix(text);

        var fields = new Dictionary<string, string>
        {
            ["file_id"] = fileId,
            ["encoding"] = encoding,
            ["bytes_total"] = totalBytes.ToString(),
            ["bytes_returned"] = Encoding.UTF8.GetByteCount(text).ToString(),
            ["lines_returned"] = Math.Min(lines.Length, maxLines).ToString(),
            ["truncated"] = (byteTruncated || lineTruncated || totalBytes > maxBytes).ToString(),
            ["redacted"] = "true",
            ["text"] = text,
        };
        return new ToolResult(
            snap.ScanId, snap.Revision, DateTime.UtcNow, Name,
            ToolResultStatus.Ok, [new ToolResultItem(fields)],
            Array.Empty<ToolResultGap>(),
            byteTruncated || lineTruncated || totalBytes > maxBytes, null);
    }

    // Returns the denial reason, or null when the type is approved.
    // Unknown = excluded (05 §7.1).
    private static string? ClassifyDenied(InvestigationScope scope, string path)
    {
        string name = Path.GetFileName(path);
        foreach (var marker in DeniedNameMarkers)
        {
            if (name.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                return "ExcludedContent:credential-or-profile-store";
            }
        }

        string ext = Path.GetExtension(path);
        if (DeniedExtensions.Contains(ext))
        {
            return "ExcludedContent:type";
        }

        if (ApprovedExtensions.Contains(ext))
        {
            return null;
        }

        // .txt only under log locations (05 §7.1), judged on the
        // SCOPE-RELATIVE path so machine prefixes (%TEMP%, user
        // names) can never smuggle a file in.
        if (string.Equals(ext, ".txt", StringComparison.OrdinalIgnoreCase))
        {
            string relative = path;
            foreach (var root in scope.Roots)
            {
                if (path.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                {
                    relative = path.Substring(root.Length);
                    break;
                }
            }

            if (relative.Contains("log", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            return "ExcludedContent:txt-outside-log-location";
        }

        return "ExcludedContent:unknown-type";
    }

    private static string DetectEncoding(byte[] raw)
    {
        if (raw.Length >= 2 && raw[0] == 0xFF && raw[1] == 0xFE)
        {
            return "utf-16le";
        }

        if (raw.Length >= 2 && raw[0] == 0xFE && raw[1] == 0xFF)
        {
            return "utf-16be";
        }

        return "utf-8";
    }
}
