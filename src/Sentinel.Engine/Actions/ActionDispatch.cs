using Sentinel.Engine.Policy;

namespace Sentinel.Engine.Actions;

// 05 §8 actor vocabulary, exact strings. The AI layer can only ever
// produce AgentProposedUserApproved — and only attached to an approval
// the user actually confirmed.
public static class ActionActors
{
    public const string User = "user";
    public const string Scheduled = "scheduled";
    public const string AgentProposedUserApproved = "agent-proposed+user-approved";
}

// One approved target. BrokerId is the opaque evidence ID the model
// or UI selected; ExpectedPath is the path it resolved to at approval
// time. The executor re-resolves the ID and REJECTS the item when the
// live resolution differs — IDs can never be rebound to new paths.
// Fingerprint fields are re-checked at execution (E31); the approval
// is evidence for comparison, never a shortcut.
public sealed record ActionTarget(
    string BrokerId,
    string ExpectedPath,
    string Kind,
    RiskTier ApprovedTier,
    long ExpectedSize,
    long ExpectedMtimeUtcTicks,
    string? ExpectedSigner,
    // D42: kind-specific approved payload as JSON (driver previous
    // identity + candidate for Kind "device"). Null for file targets.
    // Executors parse it strictly — malformed aux refuses the item.
    string? AuxJson = null);

// The human confirmation, as data. Built by the Confirm Sheet (E33)
// or the L3 envelope (E36) — never by the AI layer.
public sealed record ActionApproval(
    string TemplateId,
    IReadOnlyList<ActionTarget> Targets,
    IReadOnlyList<string> ScopeRoots,
    IReadOnlyList<string> ScopeExcluded,
    long Generation,
    DateTimeOffset ApprovedUtc,
    string Actor,
    string IdempotencyKey);

// Every way dispatch can refuse BEFORE any executor runs. Each one
// is an audited outcome, never a silent skip or an exception.
public enum RefusalCode
{
    None,
    TemplateUnknown,
    TemplateSuspended,
    TemplateProposed,
    TemplateNotImplemented,
    PermissionDenied,
    BatchEmpty,
    ApprovalExpired,
}

public enum BatchStatus
{
    Completed,
    Partial,
    Refused,
    Failed,
    Cancelled,
    Duplicate,
}

public enum ItemStatus
{
    Done,
    Refused,
    Failed,
    Cancelled,
}

public sealed record ItemOutcome(
    ActionTarget Target,
    ItemStatus Status,
    string Detail,
    string? RevalidationVerdict,
    string? VaultRef,
    bool UndoAvailable);

public sealed record DispatchOutcome(
    string BatchId,
    string TemplateId,
    BatchStatus Status,
    RefusalCode Refusal,
    string Detail,
    IReadOnlyList<ItemOutcome> Items,
    DateTimeOffset StartedUtc,
    DateTimeOffset FinishedUtc,
    long AuditSeq);

// What the executor reports back. The dispatcher wraps this with
// batch bookkeeping (IDs, timing, audit linkage).
public sealed record BatchExecutionResult(
    BatchStatus Status,
    IReadOnlyList<ItemOutcome> Items,
    string? Note);

public sealed record ExecutionProgress(
    int Done,
    int Total,
    string Current);

public sealed record BatchExecutionRequest(
    ActionApproval Approval,
    ActionTemplate Template,
    IBrokerIdResolver? Resolver,
    IProgress<ExecutionProgress>? Progress);

// Resolves opaque broker IDs to paths at execution time. A null
// resolver (app reopened, investigation gone) is legal: the executor
// falls back to ExpectedPath, and execution-time revalidation still
// protects the target. Close/reopen always works.
public interface IBrokerIdResolver
{
    bool TryResolve(string brokerId, out string path);
}

// 05 §8 fields, minus versions (the store stamps app/model/pack
// versions at append time from its construction wiring).
public sealed record AuditDraft(
    string Actor,
    string ActionId,
    IReadOnlyList<string> FindingIds,
    string? EvidenceHash,
    string BeforeJson,
    string AfterJson,
    string BackupRef,
    string UndoState,
    string Detail);

// Append-only audit sink. Returns false (never throws) when the
// store is unavailable — the dispatcher treats that as fail-closed:
// an action that cannot be audited cannot run.
public interface IActionAuditSink
{
    bool TryAppend(AuditDraft draft, out long seq, out string error);
}

// Per-module L0–L3 levels. Unknown modules answer L0 (deny by
// default); Drivers/Threats are capped at L2 by the provider.
public interface IPermissionLevels
{
    PermissionLevel LevelFor(string module);
}

public interface IActionExecutor
{
    Task<BatchExecutionResult> ExecuteAsync(
        BatchExecutionRequest request, CancellationToken ct);
}

// E30: the single choke point for every mutation. Deny by default:
// unknown/suspended/proposed/unimplemented templates, missing
// permission, stale approvals, and empty batches are all refused
// with a plain-language reason AND an audit entry. Executors can only
// be registered for Active templates, so a suspended or proposed
// template cannot be smuggled in through wiring.
public sealed class ActionDispatcher
{
    // How long a Confirm Sheet approval stays valid. 05 requires
    // stale approvals to abort but sets no TTL; 15 minutes bounds
    // the drift window while surviving a slow user read-through.
    public static readonly TimeSpan ApprovalTtl = TimeSpan.FromMinutes(15);

    private const int MaxIdempotencyKeys = 5000;

    private readonly IActionAuditSink _audit;
    private readonly IPermissionLevels _levels;
    private readonly Dictionary<string, IActionExecutor> _executors = new(StringComparer.Ordinal);
    private readonly HashSet<string> _seenKeys = new(StringComparer.Ordinal);
    private readonly Queue<string> _keyOrder = new();
    private readonly object _gate = new();

    public ActionDispatcher(IActionAuditSink audit, IPermissionLevels levels)
    {
        _audit = audit;
        _levels = levels;
    }

    // Structural guarantee: only Active templates accept an executor.
    // Returns false for anything else — the template stays refused.
    public bool RegisterExecutor(string templateId, IActionExecutor executor)
    {
        var template = ActionRegistry.Find(templateId);
        if (template is null || template.Status != TemplateStatus.Active)
        {
            return false;
        }

        lock (_gate)
        {
            _executors[template.Id] = executor;
        }

        return true;
    }

    public async Task<DispatchOutcome> DispatchAsync(
        ActionApproval approval, IBrokerIdResolver? resolver, CancellationToken ct,
        IProgress<ExecutionProgress>? progress = null)
    {
        var started = DateTimeOffset.UtcNow;
        string batchId = Guid.NewGuid().ToString("N");

        if (ct.IsCancellationRequested)
        {
            return Refused(batchId, approval, started,
                RefusalCode.None, BatchStatus.Cancelled,
                "Cancelled before anything started — nothing was done.");
        }

        var template = ActionRegistry.Find(approval.TemplateId);
        if (template is null)
        {
            return Refused(batchId, approval, started,
                RefusalCode.TemplateUnknown, BatchStatus.Refused,
                $"'{approval.TemplateId}' is not a known action — nothing was done.");
        }

        switch (template.Status)
        {
            case TemplateStatus.Suspended:
                return Refused(batchId, approval, started,
                    RefusalCode.TemplateSuspended, BatchStatus.Refused,
                    $"'{template.Title}' is suspended and cannot run — nothing was done.");
            case TemplateStatus.Proposed:
                return Refused(batchId, approval, started,
                    RefusalCode.TemplateProposed, BatchStatus.Refused,
                    $"'{template.Title}' is proposed but not yet approved for use — nothing was done.");
            case TemplateStatus.Registered:
                return Refused(batchId, approval, started,
                    RefusalCode.TemplateNotImplemented, BatchStatus.Refused,
                    $"'{template.Title}' is registered but its executor is not built yet — nothing was done.");
            case TemplateStatus.Active:
                break;
            default:
                return Refused(batchId, approval, started,
                    RefusalCode.TemplateUnknown, BatchStatus.Refused,
                    $"'{template.Id}' has an unrecognized status — nothing was done.");
        }

        if (approval.Targets.Count == 0)
        {
            return Refused(batchId, approval, started,
                RefusalCode.BatchEmpty, BatchStatus.Refused,
                "The approval named no items — nothing was done.");
        }

        if (_levels.LevelFor(template.Module) < template.MinLevel)
        {
            return Refused(batchId, approval, started,
                RefusalCode.PermissionDenied, BatchStatus.Refused,
                $"The {template.Module} permission (L{(int)_levels.LevelFor(template.Module)}) is below " +
                $"the L{(int)template.MinLevel} this action needs — nothing was done.");
        }

        if (UtcNow() - approval.ApprovedUtc > ApprovalTtl)
        {
            return Refused(batchId, approval, started,
                RefusalCode.ApprovalExpired, BatchStatus.Refused,
                "This confirmation expired — please review the items again. Nothing was done.");
        }

        lock (_gate)
        {
            if (!string.IsNullOrEmpty(approval.IdempotencyKey)
                && _seenKeys.Contains(approval.IdempotencyKey))
            {
                return Refused(batchId, approval, started,
                    RefusalCode.None, BatchStatus.Duplicate,
                    "This exact approval already ran — it was not run twice.");
            }
        }

        IActionExecutor? executor;
        lock (_gate)
        {
            _executors.TryGetValue(template.Id, out executor);
        }

        if (executor is null)
        {
            return Refused(batchId, approval, started,
                RefusalCode.TemplateNotImplemented, BatchStatus.Refused,
                $"'{template.Title}' has no executor wired — nothing was done.");
        }

        RememberKey(approval.IdempotencyKey);

        BatchExecutionResult result;
        try
        {
            result = await executor.ExecuteAsync(
                new BatchExecutionRequest(approval, template, resolver, progress), ct);
        }
        catch (OperationCanceledException)
        {
            return Audited(batchId, approval, template.Id, started, BatchStatus.Cancelled,
                RefusalCode.None, "Cancelled — items already moved stay recoverable via Undo.",
                []);
        }
        catch (Exception ex)
        {
            return Audited(batchId, approval, template.Id, started, BatchStatus.Failed,
                RefusalCode.None, $"The action failed safely ({ex.GetType().Name}) — see item details.",
                []);
        }

        return Audited(batchId, approval, template.Id, started, result.Status,
            RefusalCode.None, result.Note ?? BatchNote(result.Status, result.Items),
            result.Items);
    }

    private DispatchOutcome Refused(
        string batchId, ActionApproval approval, DateTimeOffset started,
        RefusalCode refusal, BatchStatus status, string detail)
    {
        string templateId = ActionRegistry.Find(approval.TemplateId)?.Id ?? approval.TemplateId;
        return Audited(batchId, approval, templateId, started, status, refusal, detail, []);
    }

    private DispatchOutcome Audited(
        string batchId, ActionApproval approval, string templateId, DateTimeOffset started,
        BatchStatus status, RefusalCode refusal, string detail,
        IReadOnlyList<ItemOutcome> items)
    {
        var finished = DateTimeOffset.UtcNow;
        long seq = -1;
        if (!_audit.TryAppend(new AuditDraft(
            Actor: approval.Actor,
            ActionId: templateId,
            FindingIds: items.Select(i => i.Target.BrokerId).Distinct().ToList(),
            EvidenceHash: null,
            BeforeJson: string.Empty,
            AfterJson: string.Empty,
            BackupRef: "none",
            UndoState: refusal == RefusalCode.None && status is BatchStatus.Completed or BatchStatus.Partial
                ? "See item outcomes"
                : "NotApplicable",
            Detail: $"[{status}{(refusal == RefusalCode.None ? string.Empty : "/" + refusal)}] {detail}"),
            out seq, out string error))
        {
            // Fail closed: the refusal/executor outcome stands, but the
            // caller learns the audit trail itself is broken.
            detail += $" WARNING: this outcome could not be written to the audit log ({error}).";
        }

        return new DispatchOutcome(batchId, templateId, status, refusal,
            detail, items, started, finished, seq);
    }

    private void RememberKey(string key)
    {
        if (string.IsNullOrEmpty(key))
        {
            return;
        }

        lock (_gate)
        {
            if (_seenKeys.Add(key))
            {
                _keyOrder.Enqueue(key);
            }

            while (_keyOrder.Count > MaxIdempotencyKeys && _keyOrder.TryDequeue(out string? old))
            {
                _seenKeys.Remove(old);
            }
        }
    }

    private static string BatchNote(BatchStatus status, IReadOnlyList<ItemOutcome> items)
    {
        int done = items.Count(i => i.Status == ItemStatus.Done);
        return status switch
        {
            BatchStatus.Completed => $"All {done} item(s) completed.",
            BatchStatus.Partial => $"{done} of {items.Count} item(s) completed — see item details.",
            BatchStatus.Cancelled => "Cancelled — items already moved stay recoverable via Undo.",
            _ => $"{status}: {done} of {items.Count} item(s) done.",
        };
    }

    // Separated for tests (approval-age boundaries use fixed times).
    private static DateTimeOffset UtcNow() => DateTimeOffset.UtcNow;
}
