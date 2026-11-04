using System.Text.Json;
using Sentinel.Engine.Actions;
using Sentinel.Store;

namespace Sentinel.App.Services;

// E34: adapts the audit log to the dispatcher's sink. Fail-closed:
// any store failure maps to false + reason (never throws), and the
// dispatcher refuses to act on an unaudited outcome.
public sealed class AuditLogSink : IActionAuditSink
{
    private readonly Func<ActionAuditLog?> _log;

    public AuditLogSink(Func<ActionAuditLog?> log)
    {
        _log = log;
    }

    public bool TryAppend(AuditDraft draft, out long seq, out string error)
    {
        seq = -1;
        try
        {
            var log = _log();
            if (log is null)
            {
                error = "audit log unavailable";
                return false;
            }

            seq = log.Append(
                DateTime.UtcNow.ToString("o"),
                draft.Actor, draft.ActionId,
                JsonSerializer.Serialize(draft.FindingIds),
                draft.EvidenceHash, draft.BeforeJson, draft.AfterJson,
                draft.BackupRef, draft.UndoState, draft.Detail);
            error = string.Empty;
            return true;
        }
        catch (Exception ex)
        {
            seq = -1;
            error = ex.GetType().Name + ": " + ex.Message;
            return false;
        }
    }
}
