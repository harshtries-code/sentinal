using System.Text.Json;
using Sentinel.Store;

namespace Sentinel.Engine.Agent;

// Runs the bounded read-only investigation loop alongside a scan
// (10 §3–§4): build context → model turn → broker-validated tool
// or evidence-checked finding → checkpoint. provisional findings
// reconcile against the committed final generation before trust.
//
// The coordinator NEVER mutates inspected objects, NEVER holds a
// DB transaction, and NEVER blocks enumeration: it reads hub
// snapshots and the live filesystem through tools.
public sealed class InvestigationCoordinator
{
    public const int MaxHistoryTurns = 10;
    public const int EmptyTurnLimit = 3;

    private readonly InvestigationScope _scope;
    private readonly string _goal;
    private readonly EvidencePreviewHub _hub;
    private readonly ToolBroker _broker;
    private readonly IInvestigationModel _model;
    private readonly AgentStore _store;
    private readonly InvestigationBudgets _budgets;
    private readonly PayloadLog _payloads;
    private readonly List<string> _history = new();
    private readonly List<AgentFinding> _findings = new();
    private readonly Queue<string> _recentResults = new();
    private int _emptyTurns;

    public InvestigationCoordinator(
        string investigationId,
        IReadOnlyList<string> roots,
        string goal,
        EvidencePreviewHub hub,
        ToolBroker broker,
        IInvestigationModel model,
        AgentStore store,
        InvestigationBudgets budgets,
        PayloadLog payloads,
        IReadOnlyList<string>? excluded = null)
    {
        InvestigationId = investigationId;
        _scope = new InvestigationScope(investigationId, roots, excluded);
        Roots = roots.ToList();
        Excluded = (excluded ?? []).ToList();
        _goal = goal;
        _hub = hub;
        _broker = broker;
        _model = model;
        _store = store;
        _budgets = budgets;
        _payloads = payloads;
    }

    public string InvestigationId { get; }

    public IReadOnlyList<string> Roots { get; }

    public IReadOnlyList<string> Excluded { get; }

    // A11: the scope this coordinator enforces, as the checkpoint
    // fingerprint. Resume compares it against the stored value.
    public string ComputeScopeFingerprint() =>
        ScopeFingerprint.Compute(Roots, Excluded);

    public InvestigationStatus Status { get; private set; } = InvestigationStatus.Investigating;

    public string? StatusDetail { get; private set; }

    public IReadOnlyList<AgentFinding> Findings => _findings;

    // Read-only budget view (a copy): lets callers display and
    // tests assert the durable counters without touching them.
    public BudgetSnapshot BudgetSnapshot => _budgets.Snapshot();

    // Raised synchronously on the investigator thread each time a
    // provisional finding persists (P1-01). Subscribers marshal to
    // the UI thread themselves. Never raised for rejected drafts.
    public event Action<AgentFinding>? ProvisionalFinding;

    // Resume from a checkpoint with a COLD model context: no history
    // replay, only the durable summary. This is the provider-cache-
    // eviction case by construction (10 §3).
    public static InvestigationCoordinator Resume(
        AgentStore store,
        string investigationId,
        IReadOnlyList<string> roots,
        EvidencePreviewHub hub,
        ToolBroker broker,
        IInvestigationModel model,
        InvestigationBudgets budgets,
        PayloadLog payloads,
        IReadOnlyList<string>? excluded = null)
    {
        var state = store.GetInvestigation(investigationId)
            ?? throw new InvalidOperationException("UnknownInvestigation");
        // A11: scope continuity is verified, not assumed. A changed
        // root, a changed exclusion set, or a legacy checkpoint
        // without a fingerprint refuses to resume: the caller starts
        // a fresh investigation instead of continuing under the
        // wrong scope. Status is NOT gated here — reopening a
        // finished investigation for its findings stays legal.
        string current = ScopeFingerprint.Compute(roots, excluded);
        if (state.ScopeFingerprint is null
            || !string.Equals(state.ScopeFingerprint, current, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("ScopeChanged");
        }

        // P25: the scope gate above passed, so pre-restart opaque
        // IDs may resolve again. Restored IDs still pass through
        // ResolveScopedPath on every use (scope, exclusion, and
        // reparse revalidation are never skipped for old IDs).
        broker.ImportIds(store.GetBrokerIds(investigationId));

        var resumed = new InvestigationCoordinator(
            investigationId, roots, state.Goal, hub, broker, model,
            store, budgets, payloads, excluded);
        budgets.Restore(new BudgetSnapshot(
            state.ToolCalls, state.EvidenceBytes, state.ElapsedSeconds,
            state.InputTokens, state.OutputTokens, state.ReasoningTokens,
            state.CachedTokens, state.TransmittedBytes,
            state.HasProviderUsage));
        foreach (var row in store.GetFindings(investigationId))
        {
            var ev = new List<CitedEvidence>();
            try
            {
                using var doc = JsonDocument.Parse(row.EvidenceIdsJson);
                foreach (var el in doc.RootElement.EnumerateArray())
                {
                    ev.Add(new CitedEvidence(
                        el.GetProperty("id").GetString() ?? string.Empty,
                        el.GetProperty("path").GetString() ?? string.Empty,
                        el.GetProperty("size").GetInt64(),
                        el.GetProperty("mtime").GetInt64()));
                }
            }
            catch (JsonException)
            {
                // Corrupt evidence list: finding cannot be trusted.
                continue;
            }

            if (Enum.TryParse<FindingStatus>(row.Status, out var status))
            {
                resumed._findings.Add(new AgentFinding(
                    row.Id, row.Revision, status, row.Observation,
                    row.Interpretation, ev, row.Limitations,
                    row.SuggestedNext));
            }
        }

        resumed._history.Add($"resumed: {_findingsSummary(resumed)}");
        return resumed;

        static string _findingsSummary(InvestigationCoordinator c) =>
            $"{c._findings.Count} findings reloaded, context cold";
    }

    public async Task<InvestigationStatus> RunAsync(CancellationToken ct = default)
    {
        Checkpoint("Investigating", null);
        try
        {
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                _budgets.Check();

                // Fresh overview per turn through the broker: audited,
                // bounded, charged, revision-stamped like any tool result.
                var overview = _broker.Dispatch(
                    _scope,
                    new ToolCallRequest(
                        "get_scan_overview",
                        new Dictionary<string, string>()),
                    _budgets, ct);
                var context = new ModelContext(
                    SecretRedactor.RedactUserPrefix(_goal),
                    string.Join(";", _scope.Roots.Select(SecretRedactor.RedactUserPrefix)),
                    overview.EvidenceRevision,
                    _hub.IsComplete,
                    ModelContextSerializer.SerializeResult(overview),
                    _broker.Tools.Select(t => t.Name + ": " + t.Description).ToList(),
                    _history.TakeLast(MaxHistoryTurns).ToList(),
                    _recentResults.ToList(),
                    _budgets.ToolCalls, _budgets.MaxToolCalls,
                    _budgets.EvidenceBytes, _budgets.MaxEvidenceBytes);
                string contextJson = ModelContextSerializer.Serialize(context);
                // A05 preview: assembled locally, not sent yet. Goal +
                // scope redacted above; tool text redacted at the boundary.
                _payloads.Append(
                    "model-request", contextJson, "this PC (preview, not sent)",
                    "C+F", redacted: true, truncated: false);

                ModelTurn turn;
                try
                {
                    turn = await _model.GetNextStepAsync(contextJson, ct).ConfigureAwait(false);
                }
                catch (ModelUnavailableException ex)
                {
                    return Finish(InvestigationStatus.Unavailable, ex.Message);
                }

                // A05: the parsed turn, kept locally. Model output —
                // no boundary redaction is applied to it.
                _payloads.Append(
                    "model-response",
                    JsonSerializer.Serialize(turn, ModelContextSerializer.Relaxed),
                    "this PC (parsed turn)", "model output",
                    redacted: false, truncated: false);

                if (turn.ToolRequest is not null)
                {
                    _emptyTurns = 0;
                    var result = _broker.Dispatch(_scope, turn.ToolRequest, _budgets, ct);
                    RememberResult(turn.ToolRequest.ToolName, result);
                    var ids = result.Items
                        .SelectMany(i => i.Fields)
                        .Where(kv => kv.Key is "id" or "file_id" or "dir_id"
                            && !string.IsNullOrEmpty(kv.Value))
                        .Select(kv => kv.Value)
                        .Distinct()
                        .Take(5);
                    _history.Add($"tool {turn.ToolRequest.ToolName} -> {result.Status} " +
                        $"{result.Items.Count} items rev {result.EvidenceRevision} " +
                        $"ids=[{string.Join(",", ids)}]");
                }
                else if (turn.Finding is not null)
                {
                    _emptyTurns = 0;
                    AcceptFinding(turn.Finding, overview.EvidenceRevision);
                }
                else if (turn.Finished)
                {
                    return Finish(InvestigationStatus.Done, turn.Note);
                }
                else
                {
                    _emptyTurns++;
                    _history.Add("empty turn: " + (turn.Note ?? "no action"));
                    if (_emptyTurns >= EmptyTurnLimit)
                    {
                        return Finish(InvestigationStatus.Done, "Model went quiet.");
                    }
                }

                Checkpoint("Investigating", null);
            }
        }
        catch (OperationCanceledException)
        {
            return Finish(InvestigationStatus.Cancelled, "Cancelled by caller.");
        }
        catch (BudgetExhaustedException ex)
        {
            return Finish(InvestigationStatus.OverBudget, ex.Message);
        }
        catch (Exception ex)
        {
            return Finish(InvestigationStatus.Failed, ex.GetType().Name);
        }
    }

    // Re-resolves every provisional finding against the COMMITTED
    // final generation AND the live filesystem. Confirmed only when
    // the store agrees the evidence was seen in that generation with
    // matching identity AND the live object still matches what was
    // cited; anything else goes stale. Never silently kept.
    public async Task ReconcileAsync(SentinelDb db, int generation, CancellationToken ct = default)
    {
        await Task.Yield();
        for (int i = 0; i < _findings.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var finding = _findings[i];
            if (finding.Status != FindingStatus.Provisional)
            {
                continue;
            }

            bool ok = finding.Evidence.Count > 0;
            foreach (var ev in finding.Evidence)
            {
                if (!LiveMatches(ev))
                {
                    ok = false;
                    break;
                }

                var fp = db.GetFingerprint(ev.Path);
                if (fp is null
                    || fp.LastSeenGeneration != generation
                    || fp.Size != ev.Size
                    || fp.MTimeUtcTicks != ev.MTimeUtcTicks)
                {
                    ok = false;
                    break;
                }
            }

            _findings[i] = finding with
            {
                Status = ok ? FindingStatus.Confirmed : FindingStatus.Stale,
            };
            PersistFinding(_findings[i]);
        }

        int confirmed = _findings.Count(f => f.Status == FindingStatus.Confirmed);
        int stale = _findings.Count(f => f.Status == FindingStatus.Stale);
        StatusDetail = $"gen {generation}: {confirmed} confirmed, {stale} stale";
        Checkpoint(Status.ToString(), StatusDetail, generation);
    }

    private static bool LiveMatches(CitedEvidence ev)
    {
        try
        {
            var info = new FileInfo(ev.Path);
            return info.Exists
                && info.Length == ev.Size
                && info.LastWriteTimeUtc.Ticks == ev.MTimeUtcTicks;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    // The model reasons over recent RESULT BODIES, not just
    // one-line history: without this, excerpts would never inform
    // findings. Bounded (last 3, 8 KiB each) so context cannot grow
    // without limit; full detail stays local and re-queryable.
    private void RememberResult(string toolName, ToolResult result)
    {
        string json = ModelContextSerializer.SerializeResult(result);
        if (json.Length > 8192)
        {
            json = json.Substring(0, 8192) + "…[result-truncated-in-context]";
        }

        _recentResults.Enqueue(toolName + ": " + json);
        while (_recentResults.Count > 3)
        {
            _recentResults.Dequeue();
        }
    }

    private void AcceptFinding(FindingDraft draft, int revision)
    {
        // P25: prose policy before identity work — a deletion
        // directive is rejected without touching the filesystem,
        // and rejected drafts are never persisted.
        if (FindingProseGuard.DraftRecommendsDeletion(draft))
        {
            _history.Add("finding REJECTED: prose recommends deletion");
            return;
        }

        var cited = new List<CitedEvidence>();
        foreach (var id in draft.EvidenceIds)
        {
            if (!_broker.TryResolveId(id, out var path) || !_scope.Contains(path))
            {
                _history.Add($"finding REJECTED: unknown/out-of-scope evidence '{id}'");
                return;
            }

            long size;
            long mtime;
            try
            {
                var info = new FileInfo(path);
                size = info.Length;
                mtime = info.LastWriteTimeUtc.Ticks;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _history.Add($"finding REJECTED: evidence '{id}' unreadable ({ex.GetType().Name})");
                return;
            }

            cited.Add(new CitedEvidence(id, path, size, mtime));
        }

        if (cited.Count == 0)
        {
            _history.Add("finding REJECTED: no evidence cited");
            return;
        }

        var finding = new AgentFinding(
            Guid.NewGuid().ToString("N"), revision, FindingStatus.Provisional,
            draft.Observation, draft.Interpretation, cited,
            draft.Limitations, draft.SuggestedNextInspection);
        _findings.Add(finding);
        PersistFinding(finding);
        _history.Add($"finding {finding.Id} provisional ({cited.Count} evidence)");
    }

    private void PersistFinding(AgentFinding finding)
    {
        // P25: the ID map first — a crash between the two writes
        // must never leave a finding citing forgotten IDs.
        _store.ReplaceBrokerIds(InvestigationId, _broker.ExportIds());
        var ev = finding.Evidence.Select(e => new Dictionary<string, object>
        {
            ["id"] = e.EvidenceId,
            ["path"] = e.Path,
            ["size"] = e.Size,
            ["mtime"] = e.MTimeUtcTicks,
        }).ToList();
        _store.UpsertFinding(
            finding.Id, InvestigationId, finding.Revision,
            finding.Status.ToString(), finding.Observation,
            finding.Interpretation, JsonSerializer.Serialize(ev),
            finding.Limitations, finding.SuggestedNextInspection);
        ProvisionalFinding?.Invoke(finding);
    }

    private InvestigationStatus Finish(InvestigationStatus status, string? detail)
    {
        Status = status;
        StatusDetail = detail;
        Checkpoint(status.ToString(), detail);
        return status;
    }

    private void Checkpoint(string status, string? detail, int committedGeneration = 0)
    {
        var unresolved = _findings
            .Where(f => f.Status == FindingStatus.Provisional
                && !string.IsNullOrWhiteSpace(f.SuggestedNextInspection))
            .Select(f => f.SuggestedNextInspection)
            .ToList();
        int committed = committedGeneration != 0
            ? committedGeneration
            : _store.GetInvestigation(InvestigationId)?.CommittedGeneration ?? 0;
        // P25: checkpoint the ID map too, so tool-only sessions
        // (no findings yet) still resume with resolvable IDs.
        _store.ReplaceBrokerIds(InvestigationId, _broker.ExportIds());
        // Scalars, not the snapshot record: the store must not take
        // an Engine dependency (Engine -> Store only).
        var snap = _budgets.Snapshot();
        _store.UpsertInvestigation(
            InvestigationId, string.Join(";", _scope.Roots), _goal,
            status, detail, _hub.Revision, committed,
            snap.ToolCalls, snap.EvidenceBytes, snap.ElapsedSeconds,
            snap.InputTokens, snap.OutputTokens, snap.ReasoningTokens,
            snap.CachedTokens, snap.TransmittedBytes,
            snap.HasProviderUsage, _budgets.EstimatedCostUsd,
            JsonSerializer.Serialize(unresolved),
            ComputeScopeFingerprint());
    }
}
