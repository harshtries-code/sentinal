using System.Text.Json;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.Engine.Actions;

// Approved restore payload (ActionTarget.AuxJson for Kind
// "quarantine"). Name is the EXACT quarantine identity from the
// current list — parsed strictly, matched exactly.
public sealed record QuarantineRestoreAux(string? Name)
{
    public static QuarantineRestoreAux? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<QuarantineRestoreAux>(json);
        }
        catch
        {
            return null;
        }
    }

    public string ToJson() => JsonSerializer.Serialize(this);
}

// T52: the quarantine_restore executor. Per item: kind + aux
// parse → elevation → tool discovery → CURRENT quarantine
// re-read with exact-name identity recheck → launch
// `MpCmdRun -Restore -Name "<exact>"` → exit interpretation →
// list re-read proving the name is gone. Restore is
// Defender-owned: Sentinel cannot re-quarantine (no supported
// MpCmdRun verb — DEC-REQUARANTINE); a Defender scan re-detects
// restored threats. States: restored, launched (verify on
// refresh), refused, failed, cancelled (pre-launch only).
public sealed class QuarantineRestoreExecutor : IActionExecutor
{
    public const string TemplateId = "quarantine_restore";

    private readonly IDefenderProcess _process;
    private readonly Func<IReadOnlyList<QuarantineRecord>> _quarantineReader;
    private readonly IActionAuditSink _audit;
    private readonly Func<string?>? _exeLocator;
    private readonly Func<bool>? _elevationProbe;
    private readonly int _settleMs;

    public QuarantineRestoreExecutor(
        IDefenderProcess process,
        Func<IReadOnlyList<QuarantineRecord>> quarantineReader,
        IActionAuditSink audit,
        Func<string?>? exeLocator = null,
        Func<bool>? elevationProbe = null,
        int settleMs = 15000)
    {
        _process = process;
        _quarantineReader = quarantineReader;
        _audit = audit;
        _exeLocator = exeLocator;
        _elevationProbe = elevationProbe;
        _settleMs = settleMs;
    }

    // Restore exit semantics: 0 = restored; anything else =
    // failure, formatted as HRESULT when negative.
    internal static (bool Restored, string Detail) InterpretRestoreExit(int exitCode) =>
        exitCode == 0
            ? (true, "Defender restored the item.")
            : (false, exitCode < 0
                ? $"Restore failed (HRESULT 0x{exitCode:X8})."
                : $"Restore failed (exit {exitCode}).");

    public async Task<BatchExecutionResult> ExecuteAsync(
        BatchExecutionRequest request, CancellationToken ct)
    {
        await Task.CompletedTask;

        var approval = request.Approval;
        if (request.Template.Id != TemplateId)
        {
            return new BatchExecutionResult(BatchStatus.Failed, [],
                $"Wrong executor: quarantine restore cannot run '{request.Template.Id}'. Nothing was done.");
        }

        var items = new List<ItemOutcome>();
        int done = 0;
        int failed = 0;
        bool cancelled = false;

        for (int i = 0; i < approval.Targets.Count; i++)
        {
            if (ct.IsCancellationRequested)
            {
                cancelled = true;
                for (int j = i; j < approval.Targets.Count; j++)
                {
                    items.Add(new ItemOutcome(approval.Targets[j], ItemStatus.Cancelled,
                        "Cancelled before this restore was requested — the item stays quarantined.",
                        null, null, false));
                }

                break;
            }

            ItemOutcome outcome;
            try
            {
                outcome = ExecuteOne(approval, request.Template, approval.Targets[i], ct);
            }
            catch (Exception ex)
            {
                string detail = $"Unexpected failure ({ex.GetType().Name}): {ex.Message} — " +
                    "Defender itself is unaffected; check Windows Security for quarantine state.";
                Audit(approval, request.Template, approval.Targets[i],
                    BeforeJson("unknown"), "Unknown restore failed before launch.", detail);
                outcome = new ItemOutcome(approval.Targets[i], ItemStatus.Failed,
                    detail, null, null, false);
            }

            items.Add(outcome);
            if (outcome.Status == ItemStatus.Done)
            {
                done++;
            }
            else if (outcome.Status == ItemStatus.Failed)
            {
                failed++;
            }

            request.Progress?.Report(new ExecutionProgress(
                items.Count, approval.Targets.Count, approval.Targets[i].ExpectedPath));
        }

        BatchStatus status = cancelled ? BatchStatus.Cancelled
            : done == items.Count && items.Count > 0 ? BatchStatus.Completed
            : done > 0 ? BatchStatus.Partial
            : failed > 0 ? BatchStatus.Failed
            : BatchStatus.Refused;
        string note = status switch
        {
            BatchStatus.Completed => "Restore(s) completed — see item details for restored vs verify-on-refresh.",
            BatchStatus.Partial => $"{done} of {items.Count} restore(s) completed — see item details.",
            BatchStatus.Refused => "Every restore was refused with a reason — quarantine unchanged.",
            BatchStatus.Failed => "The run failed — see item details.",
            BatchStatus.Cancelled => $"Cancelled after {done} restore(s). Unrequested items stay quarantined.",
            _ => status.ToString(),
        };
        return new BatchExecutionResult(status, items, note);
    }

    private ItemOutcome ExecuteOne(
        ActionApproval approval,
        ActionTemplate template,
        ActionTarget target,
        CancellationToken ct)
    {
        if (!string.Equals(target.Kind, "quarantine", StringComparison.OrdinalIgnoreCase))
        {
            return AuditRefused(approval, template, target,
                $"Only quarantined items can restore here (this target is '{target.Kind}'). Nothing was done.",
                "Kind/Wrong");
        }

        var aux = QuarantineRestoreAux.Parse(target.AuxJson);
        if (aux is null || string.IsNullOrWhiteSpace(aux.Name))
        {
            return AuditRefused(approval, template, target,
                "The approval payload for this restore names no quarantined item — nothing was done.",
                "Aux/Malformed");
        }

        string name = aux.Name.Trim();
        bool elevated = _elevationProbe?.Invoke() ?? ElevationPolicy.IsProcessElevated();
        if (!ElevationPolicy.TemplateMayRun(template, elevated, out string elevationReason))
        {
            return AuditRefused(approval, template, target, elevationReason, "Elevation/Required");
        }

        // A provided locator answering missing stays missing —
        // it must NOT fall through to live discovery.
        string? resolved = _exeLocator is not null
            ? _exeLocator()
            : DefenderScan.ResolveExe();
        if (string.IsNullOrWhiteSpace(resolved) || !File.Exists(resolved))
        {
            return AuditRefused(approval, template, target,
                "Defender command-line tool not found on this PC — nothing was done.",
                "Tool/Missing");
        }

        // Identity recheck: the CURRENT list must still carry the
        // exact name (never the sheet-time copy, never old
        // detection history).
        IReadOnlyList<QuarantineRecord> current;
        try
        {
            current = _quarantineReader();
        }
        catch (Exception ex)
        {
            return AuditRefused(approval, template, target,
                $"Current quarantine unreadable ({ex.GetType().Name}) — refusing a blind restore.",
                "Target/Unreadable");
        }

        if (!current.Any(q => string.Equals(q.Name, name, StringComparison.Ordinal)))
        {
            return AuditRefused(approval, template, target,
                $"'{name}' is not in current quarantine (removed, restored, or renamed) — nothing was done.",
                "Target/Changed");
        }

        string exe = resolved;
        string args = "-Restore -Name \"" + name.Replace("\"", string.Empty) + "\"";
        string before = BeforeJson(name, exe, args);
        DefenderLaunch launched;
        try
        {
            launched = _process.Launch(exe, args, _settleMs, ct);
        }
        catch (Exception ex)
        {
            return AuditFailed(approval, template, target,
                $"Launch failed ({ex.GetType().Name}: {ex.Message}) — quarantine unchanged.",
                "Launch/Failed", before);
        }

        if (!launched.Started)
        {
            return AuditFailed(approval, template, target,
                $"Defender did not start: {launched.Detail}",
                "Launch/Refused", before);
        }

        if (!launched.Exited)
        {
            return AuditDone(approval, template, target, before,
                AfterJson("launched", launched.ProcessId, null, false),
                $"Restore of '{name}' requested (PID {launched.ProcessId?.ToString() ?? "?"}) — " +
                "still running; verify on the next Threats refresh.");
        }

        var (restored, exitDetail) = InterpretRestoreExit(launched.ExitCode ?? -1);
        if (!restored)
        {
            return AuditFailed(approval, template, target,
                exitDetail + " Quarantine unchanged.", "Restore/Failed", before);
        }

        // Verify: the name must be GONE from the current list.
        bool gone;
        try
        {
            gone = !_quarantineReader().Any(
                q => string.Equals(q.Name, name, StringComparison.Ordinal));
        }
        catch (Exception ex)
        {
            return AuditFailed(approval, template, target,
                $"Restore exited clean but verification failed ({ex.GetType().Name}) — " +
                "check Windows Security; treating as unverified.",
                "Restore/Unverified", before);
        }

        if (!gone)
        {
            return AuditFailed(approval, template, target,
                $"Restore exited clean but '{name}' is still listed — restore did not complete.",
                "Restore/Unverified", before);
        }

        return AuditDone(approval, template, target, before,
            AfterJson("restored", launched.ProcessId, launched.ExitCode, true),
            $"Defender restored '{name}' — no longer in quarantine. " +
            "A Defender scan re-detects it if it is still a threat.");
    }

    private ItemOutcome AuditDone(
        ActionApproval approval,
        ActionTemplate template,
        ActionTarget target,
        string before,
        string after,
        string detail)
    {
        Audit(approval, template, target, before, after, detail);
        return new ItemOutcome(target, ItemStatus.Done, detail, "Ok/None", null, false);
    }

    private ItemOutcome AuditRefused(
        ActionApproval approval,
        ActionTemplate template,
        ActionTarget target,
        string detail,
        string verdict)
    {
        Audit(approval, template, target, BeforeJson(target.ExpectedPath),
            "Restore refused before launch.", detail);
        return new ItemOutcome(target, ItemStatus.Refused, detail, verdict, null, false);
    }

    private ItemOutcome AuditFailed(
        ActionApproval approval,
        ActionTemplate template,
        ActionTarget target,
        string detail,
        string verdict,
        string before)
    {
        Audit(approval, template, target, before, "Restore did not complete.", detail);
        return new ItemOutcome(target, ItemStatus.Failed, detail, verdict, null, false);
    }

    private void Audit(
        ActionApproval approval,
        ActionTemplate template,
        ActionTarget target,
        string before,
        string after,
        string detail)
    {
        try
        {
            _audit.TryAppend(new AuditDraft(approval.Actor, template.Id,
                [target.BrokerId], null, before, after,
                "defender-owned-restore", "None", detail), out _, out _);
        }
        catch
        {
            // Best effort: a restore outcome is never un-happened
            // over a logging gap (same policy as the scan executor).
        }
    }

    private static string BeforeJson(string name) =>
        JsonSerializer.Serialize(new { restore = name });

    private static string BeforeJson(string name, string exe, string args) =>
        JsonSerializer.Serialize(new { restore = name, exe, args });

    private static string AfterJson(string state, int? pid, int? exit, bool verified) =>
        JsonSerializer.Serialize(new { state, pid, exit, verified });
}
