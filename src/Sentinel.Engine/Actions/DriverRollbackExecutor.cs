using System.Text.Json;
using System.Text.RegularExpressions;

namespace Sentinel.Engine.Actions;

using Drivers;

// D42: the driver_rollback executor. Per item: kind + aux parse →
// elevation → restore-point precondition → live re-read → rollback
// target validated (strict oemN.inf name AND present in the CURRENT
// store enum — a target that vanished refuses) → reinstall → verify
// the bad version is gone → blocklist the bad version. A rollback
// that cannot verify is Failed with the restore-point sequence; the
// rollback IS the recovery, so there is no second auto-rollback.
public sealed partial class DriverRollbackExecutor : IActionExecutor
{
    public const string TemplateId = "driver_rollback";

    private readonly IDriverOps _ops;
    private readonly ISrClient _srClient;
    private readonly Func<DriverBlocklist> _blocklistFactory;
    private readonly IActionAuditSink _audit;
    private readonly Func<bool>? _elevationProbe;
    private readonly Func<int?>? _disableSrReader;

    public DriverRollbackExecutor(
        IDriverOps ops,
        ISrClient srClient,
        Func<DriverBlocklist> blocklistFactory,
        IActionAuditSink audit,
        Func<bool>? elevationProbe = null,
        Func<int?>? disableSrReader = null)
    {
        _ops = ops;
        _srClient = srClient;
        _blocklistFactory = blocklistFactory;
        _audit = audit;
        _elevationProbe = elevationProbe;
        _disableSrReader = disableSrReader;
    }

    // Resolved per call (not cached): constructing the executor —
    // e.g. at app startup — must never touch the blocklist store.
    private DriverBlocklist Blocklist => _blocklistFactory();

    public async Task<BatchExecutionResult> ExecuteAsync(
        BatchExecutionRequest request, CancellationToken ct)
    {
        await Task.CompletedTask;

        var approval = request.Approval;
        if (request.Template.Id != TemplateId)
        {
            return new BatchExecutionResult(BatchStatus.Failed, [],
                $"Wrong executor: driver rollback cannot run '{request.Template.Id}'. Nothing was done.");
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
                        "Cancelled before this device was touched — nothing was done.",
                        null, null, false));
                }

                break;
            }

            ItemOutcome outcome;
            try
            {
                outcome = ExecuteOne(approval, request.Template, approval.Targets[i], request.Resolver);
            }
            catch (Exception ex)
            {
                string detail = $"Unexpected failure ({ex.GetType().Name}): {ex.Message} — " +
                    "the device was left as found; use System Restore if it misbehaves.";
                Audit(approval, request.Template, approval.Targets[i],
                    BeforeJson(approval.Targets[i].ExpectedPath), string.Empty,
                    "unknown", "Unknown", detail);
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
            BatchStatus.Completed => $"Rolled back all {done} device(s) — each verified after reinstall.",
            BatchStatus.Partial => $"Rolled back {done} of {items.Count} device(s) — see item details.",
            BatchStatus.Refused => "Every device was refused with a reason — nothing was changed.",
            BatchStatus.Failed => "The run failed — see item details. Restore points remain for manual recovery.",
            BatchStatus.Cancelled => $"Cancelled after {done} device(s).",
            _ => status.ToString(),
        };
        return new BatchExecutionResult(status, items, note);
    }

    private ItemOutcome ExecuteOne(
        ActionApproval approval,
        ActionTemplate template,
        ActionTarget target,
        IBrokerIdResolver? resolver)
    {
        string deviceId = target.ExpectedPath;
        if (!string.Equals(target.Kind, "device", StringComparison.OrdinalIgnoreCase))
        {
            return AuditRefused(approval, template, target,
                $"Only devices can be driver-rolled-back in v1 (this target is '{target.Kind}'). Nothing was done.",
                "Kind/Wrong");
        }

        if (resolver is not null && resolver.TryResolve(target.BrokerId, out string? liveId) &&
            !string.Equals(liveId, deviceId, StringComparison.OrdinalIgnoreCase))
        {
            return AuditRefused(approval, template, target,
                "This item no longer resolves to its approved device — nothing was done.",
                "Rebind/Changed");
        }

        var aux = DriverTargetAux.Parse(target.AuxJson);
        if (aux is null)
        {
            return AuditRefused(approval, template, target,
                "The approval payload for this device is missing or malformed — nothing was done.",
                "Aux/Malformed");
        }

        if (string.IsNullOrWhiteSpace(aux.TargetPublishedInf) ||
            !StoreInfPattern().IsMatch(aux.TargetPublishedInf))
        {
            return AuditRefused(approval, template, target,
                $"The rollback target '{aux.TargetPublishedInf ?? "none"}' is not a driver-store package name — " +
                "nothing was done.",
                "Target/BadName");
        }

        bool elevated = _elevationProbe?.Invoke() ?? ElevationPolicy.IsProcessElevated();
        if (!ElevationPolicy.TemplateMayRun(template, elevated, out string elevationReason))
        {
            return AuditRefused(approval, template, target, elevationReason, "Elevation/Required");
        }

        var capability = RestorePointManager.CheckCapability(_disableSrReader);
        if (!capability.Capable)
        {
            return AuditRefused(approval, template, target, capability.Reason, "RestorePoint/Unavailable");
        }

        var (sequence, beginError) = RestorePointManager.Begin(
            _srClient, $"Sentinel driver rollback {deviceId}");
        if (sequence is null)
        {
            return AuditFailed(approval, template, target,
                $"A restore point could not be created ({beginError}) — nothing was changed.",
                "RestorePoint/BeginFailed", "none", "None");
        }

        string backupRef = "RestorePoint:" + sequence;
        try
        {
            return ExecuteWithRestorePoint(approval, template, target, aux, deviceId, backupRef);
        }
        finally
        {
            string? endError = RestorePointManager.End(_srClient, sequence.Value);
            if (endError is not null)
            {
                Audit(approval, template, target, BeforeJson(deviceId),
                    string.Empty, backupRef, "Unknown",
                    $"Restore-point close reported: {endError} The point may still be usable.");
            }
        }
    }

    private ItemOutcome ExecuteWithRestorePoint(
        ActionApproval approval,
        ActionTemplate template,
        ActionTarget target,
        DriverTargetAux aux,
        string deviceId,
        string backupRef)
    {
        DeviceStatus live;
        try
        {
            live = _ops.ReadDevice(deviceId);
        }
        catch (Exception ex)
        {
            return AuditFailed(approval, template, target,
                $"The device could not be re-read ({ex.GetType().Name}) — nothing was changed.",
                "Device/Unreadable", backupRef, "None");
        }

        if (!live.Present)
        {
            return AuditRefused(approval, template, target,
                "The device is no longer present (unplugged or uninstalled) — nothing was done.",
                "Device/Gone");
        }

        // The target must be in the CURRENT store: a package removed
        // since approval (cleanup, another tool) refuses — reinstall
        // would fail or, worse, hit a same-named stranger.
        IReadOnlyList<StorePackage> store;
        try
        {
            store = _ops.EnumStore();
        }
        catch (Exception ex)
        {
            return AuditFailed(approval, template, target,
                $"The driver store could not be enumerated ({ex.GetType().Name}) — nothing was changed.",
                "Store/Unreadable", backupRef, "None");
        }

        bool targetInStore = store.Any(p =>
            string.Equals(p.PublishedName, aux.TargetPublishedInf, StringComparison.OrdinalIgnoreCase));
        if (!targetInStore)
        {
            return AuditRefused(approval, template, target,
                $"Rollback target {aux.TargetPublishedInf} is no longer in the driver store — " +
                "nothing was done. Another tool may have cleaned it; use System Restore instead.",
                "Target/Vanished");
        }

        string before = BeforeJson(deviceId, live, aux);

        InstallResult reinstalled;
        try
        {
            reinstalled = _ops.InstallStorePackage(aux.TargetPublishedInf!);
        }
        catch (Exception ex)
        {
            return AuditFailed(approval, template, target,
                $"Reinstall failed ({ex.GetType().Name}: {ex.Message}) — " +
                $"restore point {backupRef} remains for manual recovery.",
                "Install/Failed", backupRef, "None");
        }

        if (!reinstalled.Success)
        {
            return AuditFailed(approval, template, target,
                $"Reinstall failed: {reinstalled.Detail} Restore point {backupRef} remains for manual recovery.",
                "Install/Failed", backupRef, "None");
        }

        DeviceStatus post;
        try
        {
            post = _ops.ReadDevice(deviceId);
        }
        catch (Exception ex)
        {
            return AuditFailed(approval, template, target,
                $"The device could not be re-read after reinstall ({ex.GetType().Name}) — " +
                $"restore point {backupRef} remains for manual recovery.",
                "Verify/Unreadable", backupRef, "None");
        }

        // Verified = on the previous version (when known), otherwise
        // at least off the bad one.
        bool verified;
        if (!string.IsNullOrWhiteSpace(aux.PreviousVersion))
        {
            verified = post.Present &&
                DriverMatching.CompareVersions(post.DriverVersion, aux.PreviousVersion, out _) == 0;
        }
        else
        {
            verified = post.Present &&
                (string.IsNullOrWhiteSpace(aux.BadVersion) ||
                    DriverMatching.CompareVersions(post.DriverVersion, aux.BadVersion, out _) != 0);
        }

        if (!verified)
        {
            return AuditFailed(approval, template, target,
                (post.Present
                    ? $"Verification failed: the driver still reports '{post.DriverVersion ?? "unknown"}'. "
                    : "Verification failed: the device is gone after reinstall. ") +
                $"Restore point {backupRef} remains for manual recovery.",
                "Verify/Failed", backupRef, "None");
        }

        // The bad version is never offered again. A KNOWN source
        // blocks that channel; an UNKNOWN origin blocks BOTH
        // installable channels — a version that broke this device is
        // not re-offered from anywhere until an operator unblocks
        // it. (Link-outs are manual and never eligibility-checked,
        // so blocking that channel would be theater.)
        if (!string.IsNullOrWhiteSpace(aux.BadVersion))
        {
            BlockBadVersion(aux, aux.BadVersion!, deviceId);
        }

        string detail = $"Rolled back to {aux.TargetPublishedInf} " +
            $"({post.DriverVersion ?? "version unreported"}) and verified. " +
            (string.IsNullOrWhiteSpace(aux.BadVersion)
                ? string.Empty
                : $"Version {aux.BadVersion} is blocked from future offers. ") +
            $"Restore point {backupRef}." +
            (reinstalled.RebootRequired ? " A reboot is pending to finish." : string.Empty);
        string after = JsonSerializer.Serialize(new
        {
            device = deviceId,
            liveVersion = post.DriverVersion,
            badVersion = aux.BadVersion,
            present = post.Present,
            problemCode = post.ProblemCode,
        });
        return AuditDone(approval, template, target, before, after, backupRef, detail);
    }

    private void BlockBadVersion(DriverTargetAux aux, string badVersion, string deviceId)
    {
        string canonical = DriverBlocklist.CanonicalSource(aux.CandidateSource);
        if (string.Equals(canonical, nameof(DriverSource.WindowsUpdate), StringComparison.Ordinal) ||
            string.Equals(canonical, nameof(DriverSource.OemCatalogue), StringComparison.Ordinal))
        {
            Blocklist.Add(canonical, badVersion, deviceId, "Rolled back — never offered again.");
            return;
        }

        Blocklist.Add(DriverSource.WindowsUpdate, badVersion, deviceId,
            "Rolled back (origin channel unknown) — blocked on every installable channel.");
        Blocklist.Add(DriverSource.OemCatalogue, badVersion, deviceId,
            "Rolled back (origin channel unknown) — blocked on every installable channel.");
    }

    private ItemOutcome AuditDone(
        ActionApproval approval,
        ActionTemplate template,
        ActionTarget target,
        string before,
        string after,
        string backupRef,
        string detail)
    {
        // Same policy as the update executor: a verified change is
        // never un-done over a logging gap — the warning rides along.
        bool audited = Audit(approval, template, target, before, after,
            backupRef, "None", detail);
        if (!audited)
        {
            detail += " WARNING: the audit entry could not be written — this change is verified but unlogged.";
            return new ItemOutcome(target, ItemStatus.Done, detail, "Ok/AuditGap", null, false);
        }

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
            string.Empty, "none", "None", detail);
        return new ItemOutcome(target, ItemStatus.Refused, detail, verdict, null, false);
    }

    private ItemOutcome AuditFailed(
        ActionApproval approval,
        ActionTemplate template,
        ActionTarget target,
        string detail,
        string verdict,
        string backupRef,
        string undoState)
    {
        Audit(approval, template, target, BeforeJson(target.ExpectedPath),
            string.Empty, backupRef, undoState, detail);
        return new ItemOutcome(target, ItemStatus.Failed, detail, verdict, null, false);
    }

    private bool Audit(
        ActionApproval approval,
        ActionTemplate template,
        ActionTarget target,
        string before,
        string after,
        string backupRef,
        string undoState,
        string detail)
    {
        try
        {
            return _audit.TryAppend(new AuditDraft(approval.Actor, template.Id,
                [target.BrokerId], null, before, after, backupRef, undoState, detail),
                out _, out _);
        }
        catch
        {
            return false;
        }
    }

    private static string BeforeJson(string deviceId) =>
        JsonSerializer.Serialize(new { device = deviceId });

    private static string BeforeJson(string deviceId, DeviceStatus live, DriverTargetAux aux) =>
        JsonSerializer.Serialize(new
        {
            device = deviceId,
            badVersion = aux.BadVersion,
            liveVersion = live.DriverVersion,
            problemCode = live.ProblemCode,
            rollbackTarget = aux.TargetPublishedInf,
        });

    [GeneratedRegex("^oem\\d{1,5}\\.inf$", RegexOptions.IgnoreCase)]
    private static partial Regex StoreInfPattern();
}
