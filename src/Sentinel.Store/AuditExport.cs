using System.Net;
using System.Text;
using System.Text.Json;

namespace Sentinel.Store;

// E34: audit export builders (JSON + readable HTML). Both escape
// hostile content — entry text is untrusted (paths, model detail,
// user names all flow through it). Pure string building; the History
// page (E37) calls these and writes the bytes.
public static class AuditExport
{
    public static string BuildJson(
        IReadOnlyList<AuditEntry> entries, AuditIntegrity integrity,
        string exportedUtc, string appVersion)
    {
        var payload = new
        {
            format = "sentinel-audit/1",
            exportedUtc,
            appVersion,
            integrity = new
            {
                ok = integrity.Ok,
                brokenAtSeq = integrity.BrokenAtSeq,
                detail = integrity.Detail,
            },
            entries = entries.Select(e =>
            {
                var (detail, afterJson) = ActionAuditLog.SplitAfter(e.AfterJson);
                return new
                {
                    seq = e.Seq,
                    utc = e.Utc,
                    actor = e.Actor,
                    actionId = e.ActionId,
                    findingIdsJson = e.FindingIdsJson,
                    evidenceHash = e.EvidenceHash,
                    beforeJson = e.BeforeJson,
                    afterJson,
                    detail,
                    backupRef = e.BackupRef,
                    undoState = e.UndoState,
                    appVersion = e.AppVersion,
                    modelId = e.ModelId,
                    packVersion = e.PackVersion,
                    prevHash = e.PrevHash,
                    entryHash = e.EntryHash,
                };
            }).ToList(),
        };
        return JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
    }

    public static string BuildHtml(
        IReadOnlyList<AuditEntry> entries, AuditIntegrity integrity, string exportedUtc)
    {
        var html = new StringBuilder();
        html.Append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
        html.Append("<title>Sentinel audit export</title>");
        html.Append("<style>body{font-family:sans-serif;max-width:72em;margin:2em auto;padding:0 1em}");
        html.Append("table{border-collapse:collapse;width:100%}th,td{border:1px solid #999;");
        html.Append("padding:.4em;vertical-align:top;text-align:left}th{background:#eee}");
        html.Append(".broken{color:#a00;font-weight:bold}.ok{color:#070;font-weight:bold}</style>");
        html.Append("</head><body><h1>Sentinel audit export</h1>");
        html.Append("<p>Exported ").Append(Esc(exportedUtc)).Append(". ");
        html.Append(integrity.Ok
            ? "<span class=\"ok\">Integrity OK</span> — "
            : "<span class=\"broken\">Integrity BROKEN</span> — ");
        html.Append(Esc(integrity.Detail)).Append("</p>");
        html.Append("<table><tr><th>Seq</th><th>Time (UTC)</th><th>Actor</th><th>Action</th>");
        html.Append("<th>Detail</th><th>Backup</th><th>Undo</th><th>Hash</th></tr>");
        foreach (var e in entries)
        {
            var (detail, _) = ActionAuditLog.SplitAfter(e.AfterJson);
            html.Append("<tr><td>").Append(e.Seq).Append("</td><td>").Append(Esc(e.Utc));
            html.Append("</td><td>").Append(Esc(e.Actor)).Append("</td><td>").Append(Esc(e.ActionId));
            html.Append("</td><td>").Append(Esc(detail)).Append("</td><td>").Append(Esc(e.BackupRef));
            html.Append("</td><td>").Append(Esc(e.UndoState)).Append("</td><td><code>");
            html.Append(Esc(e.EntryHash.Length > 16 ? e.EntryHash.Substring(0, 16) + "…" : e.EntryHash));
            html.Append("</code></td></tr>");
        }

        html.Append("</table></body></html>");
        return html.ToString();
    }

    // 05 §8.1 seal archive. Carries an explicit unsigned marker —
    // signing is specified but deferred, and the archive says so
    // instead of leaving the question open.
    public static string BuildSealArchive(
        IReadOnlyList<AuditEntry> entries, string sealedUtc, string appVersion)
    {
        var payload = new
        {
            format = "sentinel-audit-seal/1",
            sealedUtc,
            appVersion,
            signature = (string?)null,
            signatureStatus = "unsigned-seal-signing-deferred",
            entryCount = entries.Count,
            entries = entries.Select(e => new
            {
                seq = e.Seq,
                utc = e.Utc,
                actor = e.Actor,
                actionId = e.ActionId,
                findingIdsJson = e.FindingIdsJson,
                evidenceHash = e.EvidenceHash,
                beforeJson = e.BeforeJson,
                afterJson = e.AfterJson,
                backupRef = e.BackupRef,
                undoState = e.UndoState,
                appVersion = e.AppVersion,
                modelId = e.ModelId,
                packVersion = e.PackVersion,
                prevHash = e.PrevHash,
                entryHash = e.EntryHash,
            }).ToList(),
        };
        return JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
    }

    private static string Esc(string value) => WebUtility.HtmlEncode(value);
}
