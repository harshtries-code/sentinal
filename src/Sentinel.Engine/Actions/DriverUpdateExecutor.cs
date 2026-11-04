using System.Text.Json;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.Engine.Actions;

using Drivers;

// D42: the driver_update_from_ladder executor. Per item: kind + aux
// parse → elevation → restore-point precondition → live re-read →
// previous-identity capture (no rollback, no update) → candidate
// re-search + eligibility → install → verify → auto-rollback +
// blocklist on verification failure. WU and OEM-catalogue sources
// only; link-out steps are manual and refuse here. Every outcome is
// audited; cancellation is honored between items.
public sealed class DriverUpdateExecutor : IActionExecutor
{
    public const string TemplateId = "driver_update_from_ladder";

    private readonly IDriverOps _ops;
    private readonly ISrClient _srClient;
    private readonly Func<DriverBlocklist> _blocklistFactory;
    private readonly IActionAuditSink _audit;
    private readonly Func<bool>? _elevationProbe;
    private readonly Func<int?>? _disableSrReader;

    public DriverUpdateExecutor(
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
                $"Wrong executor: driver update cannot run '{request.Template.Id}'. Nothing was done.");
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
                Audit(approval, request.Template, approval.Targets[i], null,
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
            BatchStatus.Completed => $"Updated all {done} device(s) — each verified after install.",
            BatchStatus.Partial => $"Updated {done} of {items.Count} device(s) — see item details.",
            BatchStatus.Refused => "Every device was refused with a reason — nothing was changed.",
            BatchStatus.Failed => "The run failed — see item details. Failed updates were rolled back where possible.",
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
                $"Only devices can be driver-updated in v1 (this target is '{target.Kind}'). Nothing was done.",
                "Kind/Wrong");
        }

        if (resolver is not null && resolver.TryResolve(target.BrokerId, out string? live) &&
            !string.Equals(live, deviceId, StringComparison.OrdinalIgnoreCase))
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
            _srClient, $"Sentinel driver update {deviceId}");
        if (sequence is null)
        {
            return AuditFailed(approval, template, target,
                $"A restore point could not be created ({beginError}) — nothing was changed.",
                "RestorePoint/BeginFailed", "none", "None");
        }

        string backupRef = "RestorePoint:" + sequence;
        try
        {
            return ExecuteWithRestorePoint(approval, template, target, aux, deviceId, sequence.Value, backupRef);
        }
        finally
        {
            string? endError = RestorePointManager.End(_srClient, sequence.Value);
            if (endError is not null)
            {
                Audit(approval, template, target, null,
                    BeforeJson(deviceId), string.Empty, backupRef, "Unknown",
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
        long sequence,
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

        if (string.IsNullOrWhiteSpace(live.DriverVersion))
        {
            return AuditRefused(approval, template, target,
                "The installed driver version could not be observed — " +
                "updating without a known rollback point is refused. Nothing was done.",
                "Identity/Unknown");
        }

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

        var (previous, identityFailure) = DriverIdentityCapture.MatchStorePackage(
            deviceId, live.HardwareIds.FirstOrDefault(),
            new DriverRecord(live.Name ?? deviceId, live.DriverVersion, live.DriverDate,
                null, null, live.HardwareIds.FirstOrDefault()),
            store);
        if (previous is null)
        {
            return AuditRefused(approval, template, target,
                identityFailure + " Nothing was done.", "Identity/NoMatch");
        }

        string undoState = "Available:Rollback:" + previous.PublishedInf;
        string before = BeforeJson(deviceId, live, previous);

        return (aux.CandidateSource ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "windows-update" or "windowsupdate" or "wu" =>
                ExecuteWindowsUpdate(approval, template, target, aux, deviceId, live,
                    previous, before, backupRef, undoState),
            "oem-catalogue" or "oemcatalogue" or "oem" or "dell-dcu" or "dcu" =>
                ExecuteOemCatalogue(approval, template, target, aux, deviceId, live,
                    previous, before, backupRef, undoState),
            _ => AuditRefused(approval, template, target,
                $"Source '{aux.CandidateSource ?? "none"}' cannot be installed by Sentinel — " +
                "vendor link-out steps are manual (open the vendor page yourself). Nothing was done.",
                "Source/LinkOut"),
        };
    }

    private ItemOutcome ExecuteWindowsUpdate(
        ActionApproval approval,
        ActionTemplate template,
        ActionTarget target,
        DriverTargetAux aux,
        string deviceId,
        DeviceStatus live,
        DriverIdentity previous,
        string before,
        string backupRef,
        string undoState)
    {
        if (string.IsNullOrWhiteSpace(aux.CandidateCatalogueId))
        {
            return AuditRefused(approval, template, target,
                "The approval names no Windows Update catalogue ID — nothing was done.",
                "Candidate/NoCatalogueId");
        }

        if (!_ops.IsNetworkAvailable())
        {
            return AuditRefused(approval, template, target,
                "No network connection — Windows Update cannot be reached. Nothing was done.",
                "Network/Down");
        }

        IReadOnlyList<DriverCandidate> results;
        try
        {
            results = _ops.SearchWindowsUpdate(deviceId, live.Name, live.HardwareIds);
        }
        catch (Exception ex)
        {
            return AuditFailed(approval, template, target,
                $"Windows Update search failed ({ex.GetType().Name}: {ex.Message}) — nothing was changed.",
                "Candidate/SearchFailed", backupRef, "None");
        }

        var candidate = results.FirstOrDefault(c =>
            string.Equals(c.CatalogueId, aux.CandidateCatalogueId, StringComparison.OrdinalIgnoreCase));
        if (candidate is null)
        {
            return AuditRefused(approval, template, target,
                "Windows Update no longer offers the approved update (it changed since approval) — " +
                "nothing was done. Re-scan the device for a fresh candidate.",
                "Candidate/Stale");
        }

        if (string.IsNullOrWhiteSpace(candidate.Version))
        {
            return AuditRefused(approval, template, target,
                "Windows Update did not report a version for this driver — " +
                "installing an unversioned driver is a blind install and is refused. Nothing was done.",
                "Candidate/Unversioned");
        }

        if (!string.IsNullOrWhiteSpace(aux.CandidateVersion) &&
            DriverMatching.CompareVersions(candidate.Version, aux.CandidateVersion, out _) != 0)
        {
            return AuditRefused(approval, template, target,
                $"The catalogue entry changed since approval ({aux.CandidateVersion} → {candidate.Version}) — " +
                "nothing was done. Re-confirm the new version first.",
                "Candidate/Changed");
        }

        var verdict = DriverMatching.CheckEligible(
            candidate, live.DriverVersion, live.HardwareIds, Blocklist.Keys);
        if (!verdict.Eligible)
        {
            return AuditRefused(approval, template, target,
                verdict.Reason + " Nothing was done.", "Candidate/Ineligible");
        }

        InstallResult installed;
        try
        {
            installed = _ops.InstallWindowsUpdate(deviceId, candidate.CatalogueId!);
        }
        catch (Exception ex)
        {
            return AuditFailed(approval, template, target,
                $"Install failed ({ex.GetType().Name}: {ex.Message}) — " +
                $"restore point {backupRef} remains for manual recovery.",
                "Install/Failed", backupRef, undoState);
        }

        if (!installed.Success)
        {
            return AuditFailed(approval, template, target,
                $"Install failed: {installed.Detail} Restore point {backupRef} remains for manual recovery.",
                "Install/Failed", backupRef, undoState);
        }

        // Verify: the live version must now equal the candidate.
        DeviceStatus post;
        try
        {
            post = _ops.ReadDevice(deviceId);
        }
        catch (Exception ex)
        {
            return RollbackAfterFailure(approval, template, target, deviceId, live, previous,
                before, backupRef, candidate,
                $"The device could not be re-read after install ({ex.GetType().Name}).");
        }

        bool versionOk = post.Present &&
            DriverMatching.CompareVersions(post.DriverVersion, candidate.Version, out _) == 0;
        if (!versionOk)
        {
            return RollbackAfterFailure(approval, template, target, deviceId, live, previous,
                before, backupRef, candidate,
                post.Present
                    ? $"Verification failed: the driver reports '{post.DriverVersion ?? "unknown"}', " +
                      $"expected '{candidate.Version}'."
                    : "Verification failed: the device is gone after install.");
        }

        string detail = $"Updated {live.DriverVersion} → {candidate.Version} via Windows Update and verified. " +
            $"Restore point {backupRef}." +
            (installed.RebootRequired ? " A reboot is pending to finish." : string.Empty);
        return AuditDone(approval, template, target, before,
            AfterJson(deviceId, post, candidate.Version), backupRef, undoState, detail);
    }

    private ItemOutcome ExecuteOemCatalogue(
        ActionApproval approval,
        ActionTemplate template,
        ActionTarget target,
        DriverTargetAux aux,
        string deviceId,
        DeviceStatus live,
        DriverIdentity previous,
        string before,
        string backupRef,
        string undoState)
    {
        _ = aux;
        OemScanSet scan;
        try
        {
            scan = _ops.ScanOemCatalogue();
        }
        catch (Exception ex)
        {
            return AuditFailed(approval, template, target,
                $"Catalogue scan failed ({ex.GetType().Name}: {ex.Message}) — nothing was changed.",
                "Candidate/SearchFailed", backupRef, "None");
        }

        if (scan.UpdateTitles.Count == 0)
        {
            return AuditRefused(approval, template, target,
                $"The OEM catalogue reports no updates ({scan.RawSummary}) — nothing was done.",
                "Candidate/Stale");
        }

        InstallResult applied;
        try
        {
            applied = _ops.ApplyOemCatalogue();
        }
        catch (Exception ex)
        {
            return AuditFailed(approval, template, target,
                $"Catalogue apply failed ({ex.GetType().Name}: {ex.Message}) — " +
                $"restore point {backupRef} remains for manual recovery.",
                "Install/Failed", backupRef, undoState);
        }

        if (!applied.Success)
        {
            return AuditFailed(approval, template, target,
                $"Catalogue apply failed: {applied.Detail} Restore point {backupRef} remains for manual recovery.",
                "Install/Failed", backupRef, undoState);
        }

        // Verify per-device: DCU reports a SET, not per-device
        // versions, so the check is presence + no NEW problem code.
        DeviceStatus post;
        try
        {
            post = _ops.ReadDevice(deviceId);
        }
        catch (Exception ex)
        {
            return RollbackAfterFailure(approval, template, target, deviceId, live, previous,
                before, backupRef, null,
                $"The device could not be re-read after the catalogue apply ({ex.GetType().Name}).");
        }

        bool problemNew = post.Present && post.ProblemCode != 0 && post.ProblemCode != live.ProblemCode;
        if (!post.Present || problemNew)
        {
            return RollbackAfterFailure(approval, template, target, deviceId, live, previous,
                before, backupRef, null,
                !post.Present
                    ? "Verification failed: the device is gone after the catalogue apply."
                    : $"Verification failed: new problem code {post.ProblemCode} " +
                      $"({post.ProblemName ?? "unnamed"}) after the catalogue apply.");
        }

        string detail = $"OEM catalogue applied ({scan.UpdateTitles.Count} update(s)) and this device " +
            $"verified present with no new problem. Restore point {backupRef}." +
            (applied.RebootRequired ? " A reboot is pending to finish." : string.Empty);
        return AuditDone(approval, template, target, before,
            AfterJson(deviceId, post, post.DriverVersion), backupRef, undoState, detail);
    }

    // Verification failed after a change: reinstall the captured
    // previous package ONCE, block the candidate so it is never
    // offered again, and report Failed with the whole narrative.
    private ItemOutcome RollbackAfterFailure(
        ActionApproval approval,
        ActionTemplate template,
        ActionTarget target,
        string deviceId,
        DeviceStatus live,
        DriverIdentity previous,
        string before,
        string backupRef,
        DriverCandidate? candidate,
        string failure)
    {
        if (candidate is not null && !string.IsNullOrWhiteSpace(candidate.Version))
        {
            Blocklist.Add(candidate.Source, candidate.Version, deviceId,
                "Failed verification after install — never offered again.");
        }

        InstallResult rolledBack;
        try
        {
            rolledBack = _ops.InstallStorePackage(previous.PublishedInf);
        }
        catch (Exception ex)
        {
            rolledBack = new InstallResult(false, false, $"{ex.GetType().Name}: {ex.Message}");
        }

        string rollbackNote;
        string finalUndo;
        if (rolledBack.Success)
        {
            DeviceStatus? post = null;
            try
            {
                post = _ops.ReadDevice(deviceId);
            }
            catch
            {
            }

            bool restored = post is { Present: true } &&
                DriverMatching.CompareVersions(post.DriverVersion, previous.Version, out _) == 0;
            rollbackNote = restored
                ? $" The previous driver ({previous.PublishedInf}, {previous.Version}) was automatically reinstalled and verified. " +
                  $"Restore point {backupRef} was kept."
                : $" The previous driver ({previous.PublishedInf}) was reinstalled but reports " +
                  $"'{post?.DriverVersion ?? "unknown"}' — use restore point {backupRef} for manual recovery.";
            finalUndo = "RolledBack:" + previous.PublishedInf;
        }
        else
        {
            rollbackNote = $" Automatic reinstall of {previous.PublishedInf} ALSO failed: {rolledBack.Detail} " +
                $"Use restore point {backupRef} for manual recovery.";
            finalUndo = "RestorePointOnly:" + backupRef;
        }

        string detail = failure + rollbackNote;
        Audit(approval, template, target, candidate?.Version, before, string.Empty,
            backupRef, finalUndo, detail);
        return new ItemOutcome(target, ItemStatus.Failed, detail, "Verify/Failed", null, false);
    }

    private ItemOutcome AuditDone(
        ActionApproval approval,
        ActionTemplate template,
        ActionTarget target,
        string before,
        string after,
        string backupRef,
        string undoState,
        string detail)
    {
        bool audited = Audit(approval, template, target, null, before, after, backupRef, undoState, detail);
        if (!audited)
        {
            // Fail-open on the LOG, not on the driver: the change is
            // verified-good, so rolling it back over a logging gap
            // would trade an audit hole for a driver outage. The
            // warning rides in the outcome instead.
            detail += " WARNING: the audit entry could not be written — this change is verified but unlogged.";
            return new ItemOutcome(target, ItemStatus.Done, detail, "Ok/AuditGap", null, true);
        }

        return new ItemOutcome(target, ItemStatus.Done, detail, "Ok/None", null, true);
    }

    private ItemOutcome AuditRefused(
        ActionApproval approval,
        ActionTemplate template,
        ActionTarget target,
        string detail,
        string verdict)
    {
        Audit(approval, template, target, null, BeforeJson(target.ExpectedPath),
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
        Audit(approval, template, target, null, BeforeJson(target.ExpectedPath),
            string.Empty, backupRef, undoState, detail);
        return new ItemOutcome(target, ItemStatus.Failed, detail, verdict, null, false);
    }

    private bool Audit(
        ActionApproval approval,
        ActionTemplate template,
        ActionTarget target,
        string? evidenceHash,
        string before,
        string after,
        string backupRef,
        string undoState,
        string detail)
    {
        try
        {
            return _audit.TryAppend(new AuditDraft(approval.Actor, template.Id,
                [target.BrokerId], evidenceHash, before, after, backupRef, undoState, detail),
                out _, out _);
        }
        catch
        {
            return false;
        }
    }

    private static string BeforeJson(string deviceId) =>
        JsonSerializer.Serialize(new { device = deviceId });

    private static string BeforeJson(string deviceId, DeviceStatus live, DriverIdentity previous) =>
        JsonSerializer.Serialize(new
        {
            device = deviceId,
            installedVersion = live.DriverVersion,
            installedDate = live.DriverDate,
            problemCode = live.ProblemCode,
            rollbackInf = previous.PublishedInf,
            rollbackVersion = previous.Version,
        });

    private static string AfterJson(string deviceId, DeviceStatus post, string? expectedVersion) =>
        JsonSerializer.Serialize(new
        {
            device = deviceId,
            liveVersion = post.DriverVersion,
            expectedVersion,
            present = post.Present,
            problemCode = post.ProblemCode,
        });
}
