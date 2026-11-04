using System.Text.Json;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.Engine.Actions;

// Approved scan payload (ActionTarget.AuxJson for Kind "scan").
// Parsed strictly — malformed aux refuses the item. Kind is one of
// quick/full/folder/offline (case-insensitive); Path only for
// folder; RestartAcknowledged only for offline.
public sealed record DefenderScanAux(
    string? Kind,
    string? Path,
    bool RestartAcknowledged)
{
    public static DefenderScanAux? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<DefenderScanAux>(json);
        }
        catch
        {
            return null;
        }
    }

    public string ToJson() => JsonSerializer.Serialize(this);
}

// T50: the defender_scan executor (process seam lives in
// DefenderScan.cs). Per item: kind + aux parse →
// offline gates (platform + restart ack) → elevation → target
// revalidation → official tool discovery → launch → 0/2/HRESULT
// interpretation → detection import. States: launched (running),
// completed-clean, completed-threats, refused, failed, cancelled.
// Remediation is ALWAYS Defender-owned: Sentinel imports results
// and changes nothing itself (BackupRef says so on every entry).
public sealed class DefenderScanExecutor : IActionExecutor
{
    public const string TemplateId = "defender_scan";

    private readonly IDefenderProcess _process;
    private readonly Func<IReadOnlyList<DefenderDetectionRecord>> _detectionsReader;
    private readonly IActionAuditSink _audit;
    private readonly Func<string?>? _exeLocator;
    private readonly Func<bool>? _elevationProbe;
    private readonly Func<int?>? _productTypeReader;
    private readonly int _settleMs;

    public DefenderScanExecutor(
        IDefenderProcess process,
        Func<IReadOnlyList<DefenderDetectionRecord>> detectionsReader,
        IActionAuditSink audit,
        Func<string?>? exeLocator = null,
        Func<bool>? elevationProbe = null,
        Func<int?>? productTypeReader = null,
        int settleMs = 5000)
    {
        _process = process;
        _detectionsReader = detectionsReader;
        _audit = audit;
        _exeLocator = exeLocator;
        _elevationProbe = elevationProbe;
        _productTypeReader = productTypeReader;
        _settleMs = settleMs;
    }

    public async Task<BatchExecutionResult> ExecuteAsync(
        BatchExecutionRequest request, CancellationToken ct)
    {
        await Task.CompletedTask;

        var approval = request.Approval;
        if (request.Template.Id != TemplateId)
        {
            return new BatchExecutionResult(BatchStatus.Failed, [],
                $"Wrong executor: defender scan cannot run '{request.Template.Id}'. Nothing was done.");
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
                        "Cancelled before this scan was requested — Defender never started.",
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
                    "Defender itself is unaffected; check Windows Security for scan state.";
                Audit(approval, request.Template, approval.Targets[i],
                    BeforeJson("unknown"), "Unknown scan failed before launch.", detail);
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
            BatchStatus.Completed => "Defender scan(s) requested — see item details for completed vs still-running.",
            BatchStatus.Partial => $"{done} of {items.Count} scan(s) requested — see item details.",
            BatchStatus.Refused => "Every scan was refused with a reason — Defender never started.",
            BatchStatus.Failed => "The run failed — see item details.",
            BatchStatus.Cancelled => $"Cancelled after {done} scan(s). Launched scans continue in Windows Security.",
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
        if (!string.Equals(target.Kind, "scan", StringComparison.OrdinalIgnoreCase))
        {
            return AuditRefused(approval, template, target,
                $"Only scans can run here (this target is '{target.Kind}'). Nothing was done.",
                "Kind/Wrong");
        }

        var aux = DefenderScanAux.Parse(target.AuxJson);
        if (aux is null || !Enum.TryParse<DefenderScanKind>(aux.Kind, ignoreCase: true, out var kind))
        {
            return AuditRefused(approval, template, target,
                "The approval payload for this scan is missing or names no known scan kind — nothing was done.",
                "Aux/Malformed");
        }

        if (kind == DefenderScanKind.Offline)
        {
            if (!DefenderScan.OfflineSupported(_productTypeReader))
            {
                return AuditRefused(approval, template, target,
                    "Offline scan is not supported on this machine (Windows 10/11 client required) — " +
                    "nothing was done.",
                    "Offline/Unsupported");
            }

            if (!aux.RestartAcknowledged)
            {
                return AuditRefused(approval, template, target,
                    "Offline scan restarts this PC into the offline environment — " +
                    "acknowledge the restart first. Nothing was done.",
                    "Offline/NoRestartAck");
            }
        }

        bool elevated = _elevationProbe?.Invoke() ?? ElevationPolicy.IsProcessElevated();
        if (!ElevationPolicy.TemplateMayRun(template, elevated, out string elevationReason))
        {
            return AuditRefused(approval, template, target, elevationReason, "Elevation/Required");
        }

        string kindLabel = KindLabel(kind, aux.Path);
        string exe;
        string args;
        if (kind == DefenderScanKind.Offline)
        {
            (exe, args) = DefenderScan.OfflineCommand();
        }
        else
        {
            if (kind == DefenderScanKind.Folder)
            {
                string full;
                try
                {
                    full = DefenderScan.ValidateFolder(aux.Path);
                }
                catch (ArgumentException ex)
                {
                    return AuditRefused(approval, template, target,
                        $"Scan target invalid ({ex.Message}) — nothing was done.",
                        "Target/Invalid");
                }
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

            exe = resolved;
            try
            {
                args = DefenderScan.BuildArguments(
                    new DefenderScanRequest(kind, aux.Path));
            }
            catch (ArgumentException ex)
            {
                return AuditRefused(approval, template, target,
                    $"Scan arguments invalid ({ex.Message}) — nothing was done.",
                    "Target/Invalid");
            }
        }

        string before = BeforeJson(kindLabel, exe, args);
        DefenderLaunch launched;
        try
        {
            launched = _process.Launch(exe, args, _settleMs, ct);
        }
        catch (Exception ex)
        {
            return AuditFailed(approval, template, target,
                $"Launch failed ({ex.GetType().Name}: {ex.Message}) — Defender never started.",
                "Launch/Failed", before);
        }

        if (!launched.Started)
        {
            return AuditFailed(approval, template, target,
                $"Defender did not start: {launched.Detail}",
                "Launch/Refused", before);
        }

        // Still running after settle: launched state. No import —
        // the scan is ongoing; results arrive on refresh.
        if (!launched.Exited)
        {
            string detail = kind == DefenderScanKind.Offline
                ? "Offline scan triggered — this PC will restart into the offline environment. " +
                  "Results import on the next Threats refresh after you sign back in."
                : $"Defender {kindLabel} launched (PID {launched.ProcessId?.ToString() ?? "?"}) — " +
                  "still running; progress shows in Windows Security. Results import on the next refresh.";
            if (launched.Detail.Contains("cancelled", StringComparison.OrdinalIgnoreCase))
            {
                detail += " (Sentinel stopped waiting on cancel; the scan itself continues.)";
            }

            return AuditDone(approval, template, target, before,
                AfterJson("launched", launched.ProcessId, null, null), detail);
        }

        var (completed, threats, exitDetail) = DefenderScan.InterpretExit(
            launched.ExitCode ?? -1);
        if (!completed)
        {
            return AuditFailed(approval, template, target,
                exitDetail + " Nothing was remediated by Sentinel.",
                "Scan/Failed", before);
        }

        string import = ImportDetections();
        string done = exitDetail + " " + import;
        return AuditDone(approval, template, target, before,
            AfterJson(threats ? "completed-threats" : "completed-clean",
                launched.ProcessId, launched.ExitCode, import),
            done);
    }

    private string ImportDetections()
    {
        IReadOnlyList<DefenderDetectionRecord> records;
        try
        {
            records = _detectionsReader();
        }
        catch (Exception ex)
        {
            return $"Detection import failed ({ex.GetType().Name}) — open Windows Security for results.";
        }

        if (records.Count == 0)
        {
            return "Defender reports no detections on record.";
        }

        var top = records
            .OrderByDescending(r => r.DetectedUtc ?? DateTime.MinValue)
            .Take(3)
            .Select(r => $"'{r.ThreatName}' ({r.DetectedUtc?.ToLocalTime().ToString("g") ?? "undated"})");
        return $"Defender reports {records.Count} detection(s) on record; most recent: {string.Join("; ", top)}.";
    }

    private static string KindLabel(DefenderScanKind kind, string? path) => kind switch
    {
        DefenderScanKind.Quick => "quick scan",
        DefenderScanKind.Full => "full scan",
        DefenderScanKind.Folder => $"folder scan ({path})",
        DefenderScanKind.Offline => "offline scan",
        _ => "scan",
    };

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
            "Scan refused before launch.", detail);
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
        Audit(approval, template, target, before, "Scan did not complete.", detail);
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
                "none-defender-owned", "None", detail), out _, out _);
        }
        catch
        {
            // Best effort: a scan outcome is never un-happened over a
            // logging gap (same policy as the driver executors).
        }
    }

    private static string BeforeJson(string kindLabel) =>
        JsonSerializer.Serialize(new { scan = kindLabel });

    private static string BeforeJson(string kindLabel, string exe, string args) =>
        JsonSerializer.Serialize(new { scan = kindLabel, exe, args });

    private static string AfterJson(string state, int? pid, int? exit, string? import) =>
        JsonSerializer.Serialize(new { state, pid, exit, import });
}
