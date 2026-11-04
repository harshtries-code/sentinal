using System.Text.Json;
using Sentinel.Engine.Agent;
using Sentinel.Engine.Policy;
using Sentinel.Store;

namespace Sentinel.Engine.Actions;

// Adapts a live ToolBroker to execution-time ID resolution. The UI
// passes null (no broker after reopen); AI-proposed actions pass the
// investigation's broker. Either way the executor rejects a live
// resolution that disagrees with the approval's expected path.
public sealed class BrokerIdResolver : IBrokerIdResolver
{
    private readonly ToolBroker _broker;

    public BrokerIdResolver(ToolBroker broker)
    {
        _broker = broker;
    }

    public bool TryResolve(string brokerId, out string path) =>
        _broker.TryResolveId(brokerId, out path);
}

// E35: the clean_items_to_vault executor — the ONLY implemented
// mutation in v1. Per item: resolve the broker ID (rebinding
// refused) → execution-time revalidation (E31) → hash → manifest
// row (InterruptedMove) → same-volume move → verify (size+hash) →
// manifest flip (Quarantined+Verified) → per-item audit entry.
// Every failure lands in a named state with the bytes accounted
// for; cancellation is honored between items; already-moved items
// stay recoverable via Undo. Batch status: Completed / Partial /
// Refused (nothing moved, nothing failed) / Failed / Cancelled /
// Duplicate (vault-level idempotency across restarts).
public sealed class CleanExecutor : IActionExecutor
{
    private readonly Func<VaultStore> _vaultFactory;
    private readonly IVaultFileIO _io;
    private readonly string _vaultRoot;
    private readonly Func<RiskClassifier> _classifierFactory;
    private readonly ISignerReader _signerReader;
    private readonly IActionAuditSink _audit;
    private readonly Func<SentinelDb>? _dbFactory;
    private readonly Func<long?>? _generationOverride;
    private readonly Func<IReadOnlyList<string>>? _orphansOverride;

    public CleanExecutor(
        Func<VaultStore> vaultFactory,
        IVaultFileIO io,
        string vaultRoot,
        Func<RiskClassifier> classifierFactory,
        ISignerReader signerReader,
        IActionAuditSink audit,
        Func<SentinelDb>? dbFactory = null,
        Func<long?>? currentGenerationOverride = null,
        Func<IReadOnlyList<string>>? orphanDirsOverride = null)
    {
        _vaultFactory = vaultFactory;
        _io = io;
        _vaultRoot = vaultRoot;
        _classifierFactory = classifierFactory;
        _signerReader = signerReader;
        _audit = audit;
        _dbFactory = dbFactory;
        _generationOverride = currentGenerationOverride;
        _orphansOverride = orphanDirsOverride;
    }

    // Resolved per call (not cached): tests swap stores between runs,
    // production's factory memoizes.
    private VaultStore Vault => _vaultFactory();

    public async Task<BatchExecutionResult> ExecuteAsync(
        BatchExecutionRequest request, CancellationToken ct)
    {
        // No awaits inside — the work is synchronous filesystem I/O.
        // The async shape keeps the dispatcher non-blocking.
        await Task.CompletedTask;

        var approval = request.Approval;
        if (request.Template.Id != "clean_items_to_vault")
        {
            return new BatchExecutionResult(BatchStatus.Failed, [],
                $"Wrong executor: clean cannot run '{request.Template.Id}'. Nothing was done.");
        }

        string batchId = Guid.NewGuid().ToString("N");
        bool trackBatch = !string.IsNullOrEmpty(approval.IdempotencyKey);
        try
        {
            if (trackBatch && !Vault.TryBeginBatch(
                    approval.IdempotencyKey, batchId, request.Template.Id,
                    DateTime.UtcNow.ToString("o"), out string? existing))
            {
                return new BatchExecutionResult(BatchStatus.Duplicate, [],
                    $"This exact approval already ran as batch {existing} — it was not run twice.");
            }
        }
        catch (Exception ex)
        {
            // The vault manifest is unreachable: fail closed before
            // touching a single file.
            return new BatchExecutionResult(BatchStatus.Failed, [],
                $"The vault manifest is unavailable ({ex.GetType().Name}) — nothing was moved.");
        }

        // One DB handle per batch feeds flags + generation + orphans.
        // A dead DB degrades to live-stat-only (conservative: orphan
        // files then refuse as Protected, generation check skips).
        SentinelDb? db = OpenDb();
        try
        {
            long? currentGeneration = _generationOverride?.Invoke() ?? ReadGeneration(db);
            var orphans = _orphansOverride?.Invoke() ?? ReadOrphans(db);
            Predicate<string>? isOrphan = orphans is null ? null : (Predicate<string>)(normalized =>
                orphans.Any(d => normalized.StartsWith(d, StringComparison.Ordinal)));
            Func<string, int>? flagsLookup = db is null
                ? null
                : (Func<string, int>)(path => SafeFlags(db, path));

            var classifier = _classifierFactory();
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
                            "Cancelled before this file was touched — nothing was done.",
                            null, null, false));
                    }

                    break;
                }

                ItemOutcome outcome;
                try
                {
                    outcome = ExecuteOne(
                        approval, request.Template, approval.Targets[i], batchId,
                        request.Resolver, classifier, currentGeneration, isOrphan, flagsLookup);
                }
                catch (Exception ex)
                {
                    // Backstop: an unexpected per-item throw must never
                    // swallow the outcomes of items that already moved
                    // (their Undo rides on those outcomes). The vault
                    // manifest row + startup recovery remain the
                    // custody backstop; this entry keeps it visible.
                    string detail = $"Unexpected failure ({ex.GetType().Name}): {ex.Message} — " +
                        "see History > Vault for custody; nothing was deleted.";
                    Audit(new AuditDraft(approval.Actor, request.Template.Id,
                        [approval.Targets[i].BrokerId], null,
                        BeforeJson(approval.Targets[i].ExpectedPath,
                            approval.Targets[i].ExpectedSize, approval.Targets[i].ApprovedTier),
                        string.Empty, "none", "NotApplicable", detail), out _);
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
                    items.Count, approval.Targets.Count,
                    Path.GetFileName(approval.Targets[i].ExpectedPath)));
            }

            BatchStatus status = cancelled ? BatchStatus.Cancelled
                : done == items.Count && items.Count > 0 ? BatchStatus.Completed
                : done > 0 ? BatchStatus.Partial
                : failed > 0 ? BatchStatus.Failed
                : BatchStatus.Refused;
            string note = status switch
            {
                BatchStatus.Completed => $"Moved all {done} file(s) to the Vault.",
                BatchStatus.Partial => $"Moved {done} of {items.Count} file(s) — see item details.",
                BatchStatus.Refused => "Every file was refused with a reason — nothing was moved.",
                BatchStatus.Failed => "The run failed — see item details. Moved files (if any) stay recoverable via Undo.",
                BatchStatus.Cancelled => $"Cancelled after {done} file(s) — moved files stay recoverable via Undo.",
                _ => status.ToString(),
            };

            if (trackBatch)
            {
                try
                {
                    Vault.FinishBatch(approval.IdempotencyKey, status.ToString(), note,
                        DateTime.UtcNow.ToString("o"));
                }
                catch (Exception ex)
                {
                    note += $" (WARNING: the batch record could not be closed: {ex.GetType().Name}.)";
                }
            }

            return new BatchExecutionResult(status, items, note);
        }
        finally
        {
            db?.Dispose();
        }
    }

    private ItemOutcome ExecuteOne(
        ActionApproval approval,
        ActionTemplate template,
        ActionTarget target,
        string batchId,
        IBrokerIdResolver? resolver,
        RiskClassifier classifier,
        long? currentGeneration,
        Predicate<string>? isVerifiedOrphan,
        Func<string, int>? flagsLookup)
    {
        if (!string.Equals(target.Kind, "file", StringComparison.OrdinalIgnoreCase))
        {
            return AuditRefused(approval, template, target,
                $"Only files can be vaulted in v1 (this target is '{target.Kind}'). Nothing was done.");
        }

        string resolved = target.ExpectedPath;
        if (resolver is not null && resolver.TryResolve(target.BrokerId, out string? live))
        {
            if (!string.Equals(live, target.ExpectedPath, StringComparison.OrdinalIgnoreCase))
            {
                return AuditRefused(approval, template, target,
                    "This item no longer resolves to its approved path — nothing was done.");
            }

            resolved = live;
        }

        var utcNow = DateTime.UtcNow;
        var check = ExecutionRevalidator.RevalidateForExecution(
            resolved, target, approval, template, classifier, utcNow,
            _signerReader, currentGeneration, isVerifiedOrphan, flagsLookup);
        if (!check.MayProceed)
        {
            return AuditRefused(approval, template, target, check.Detail,
                $"{check.Verdict}/{check.Extended}");
        }

        string preHash;
        long preSize;
        try
        {
            preHash = _io.ComputeSha256(resolved);
            preSize = _io.GetSize(resolved);
        }
        catch (Exception ex)
        {
            return AuditFailed(approval, template, target,
                $"It could not be read for the vault record ({ex.GetType().Name}: {ex.Message}) — nothing was done.");
        }

        string vaultRef = "V-" + Guid.NewGuid().ToString("N").Substring(0, 12).ToUpperInvariant();
        string volume = VaultLayout.VolumeLabelFor(Path.GetFullPath(resolved));
        string rel = VaultLayout.ItemFileName(vaultRef, Path.GetFileName(resolved));
        string dir = VaultLayout.ItemDir(_vaultRoot, volume);
        string dest = Path.Combine(dir, rel);
        string movedUtc = utcNow.ToString("o");

        try
        {
            _io.CreateDirectory(dir);
        }
        catch (Exception ex)
        {
            return AuditFailed(approval, template, target,
                $"The vault directory could not be prepared ({ex.GetType().Name}) — nothing was done.");
        }

        try
        {
            Vault.RecordItem(new VaultItem(vaultRef, batchId, resolved, rel, volume,
                preSize, preHash, movedUtc, template.Id, approval.Actor,
                VaultStatus.InterruptedMove, false, null, null, null, "moving"));
        }
        catch (Exception ex)
        {
            return AuditFailed(approval, template, target,
                $"The vault record could not be written ({ex.GetType().Name}) — nothing was moved.");
        }

        try
        {
            _io.MoveFile(resolved, dest);
        }
        catch (UnauthorizedAccessException)
        {
            Vault.MarkInterrupted(vaultRef, VaultStatus.InterruptedMove,
                "Move denied by the OS (access denied) — the original is untouched.");
            return AuditRefused(approval, template, target, ElevationPolicy.CleanDeniedReason,
                "Unreadable/ElevationRequired");
        }
        catch (Exception ex)
        {
            Vault.MarkInterrupted(vaultRef, VaultStatus.InterruptedMove,
                $"Move failed ({ex.GetType().Name}) — the original is untouched.");
            return AuditFailed(approval, template, target,
                $"The move failed ({ex.GetType().Name}: {ex.Message}) — the original is untouched.");
        }

        // Verify: hash + size of the vault copy against pre-move.
        string postHash;
        long postSize;
        try
        {
            postHash = _io.ComputeSha256(dest);
            postSize = _io.GetSize(dest);
        }
        catch (Exception ex)
        {
            return FailAfterMove(vaultRef, approval, template, target, resolved, dest,
                $"The vault copy could not be verified ({ex.GetType().Name}).");
        }

        if (postSize != preSize || !string.Equals(postHash, preHash, StringComparison.OrdinalIgnoreCase))
        {
            return FailAfterMove(vaultRef, approval, template, target, resolved, dest,
                "The vault copy failed verification (bytes differ from the original).");
        }

        Vault.MarkVerified(vaultRef);
        string detail = $"Moved to the Vault as {vaultRef} — {preSize} bytes retained, restorable via Undo.";
        if (Audit(new AuditDraft(approval.Actor, template.Id, [target.BrokerId], preHash,
                BeforeJson(resolved, preSize, target.ApprovedTier),
                AfterJson(vaultRef, dest), "Vault:" + vaultRef, "Available:Vault:" + vaultRef,
                detail), out _))
        {
            return new ItemOutcome(target, ItemStatus.Done, detail, "Ok/None", vaultRef, true);
        }

        // Fail closed: moved but unaudited — restore the original.
        try
        {
            _io.MoveFile(dest, resolved);
            Vault.MarkSuperseded(vaultRef,
                "Audit write failed after the move; the original was restored to its place. " +
                "The vault copy was moved back, not left behind.");
            return new ItemOutcome(target, ItemStatus.Failed,
                "The file was moved but the move could not be audited, so it was restored to its place. " +
                "Nothing is in the vault for this file.", "Ok/None", null, false);
        }
        catch (Exception ex)
        {
            Vault.MarkInterrupted(vaultRef, VaultStatus.InterruptedMove,
                $"AUDIT GAP: moved but unaudited, and the automatic restore failed ({ex.GetType().Name}).");
            return new ItemOutcome(target, ItemStatus.Failed,
                $"The file was moved but could not be audited, and the automatic restore ALSO failed " +
                $"({ex.GetType().Name}). The bytes are in the vault ({vaultRef}) — see History > Vault. " +
                "Nothing was deleted.", "Ok/None", vaultRef, false);
        }
    }

    // The vault copy is bad: restore the original from it ONLY when
    // the vault bytes still match the pre-move hash (a failed move
    // that left a partial copy must not overwrite a good original —
    // but the original is GONE (moved), so the choice is restore the
    // corrupt copy vs report loss. Neither is acceptable blindly: if
    // the vault copy mismatches, the original bytes may already be
    // lost — move the vault copy back (best-effort custody) and say
    // exactly what happened. The vault never deletes, so the corrupt
    // copy's fate is explicit in the row detail.
    private ItemOutcome FailAfterMove(
        string vaultRef, ActionApproval approval, ActionTemplate template,
        ActionTarget target, string resolved, string dest, string reason)
    {
        string detail;
        try
        {
            _io.MoveFile(dest, resolved);
            detail = reason + " The copy was moved back to its place — verify the file before trusting it.";
        }
        catch (Exception ex)
        {
            detail = reason + $" The copy could not be moved back either ({ex.GetType().Name}) — " +
                $"the bytes sit in the vault ({vaultRef}) unverified. Nothing was deleted.";
        }

        Vault.MarkSuperseded(vaultRef, detail);
        return AuditFailed(approval, template, target, detail);
    }

    private ItemOutcome AuditRefused(
        ActionApproval approval, ActionTemplate template, ActionTarget target,
        string detail, string? verdict = null)
    {
        if (!Audit(new AuditDraft(approval.Actor, template.Id, [target.BrokerId], null,
                BeforeJson(target.ExpectedPath, target.ExpectedSize, target.ApprovedTier),
                string.Empty, "none", "NotApplicable", detail), out _))
        {
            detail += " (WARNING: this refusal could not be written to the audit log.)";
        }

        return new ItemOutcome(target, ItemStatus.Refused, detail, verdict, null, false);
    }

    private ItemOutcome AuditFailed(
        ActionApproval approval, ActionTemplate template, ActionTarget target, string detail)
    {
        if (!Audit(new AuditDraft(approval.Actor, template.Id, [target.BrokerId], null,
                BeforeJson(target.ExpectedPath, target.ExpectedSize, target.ApprovedTier),
                string.Empty, "none", "NotApplicable", detail), out _))
        {
            detail += " (WARNING: this failure could not be written to the audit log.)";
        }

        return new ItemOutcome(target, ItemStatus.Failed, detail, null, null, false);
    }

    private bool Audit(AuditDraft draft, out long seq) =>
        _audit.TryAppend(draft, out seq, out _);

    private SentinelDb? OpenDb()
    {
        if (_dbFactory is null)
        {
            return null;
        }

        try
        {
            return _dbFactory();
        }
        catch
        {
            return null;
        }
    }

    private static long? ReadGeneration(SentinelDb? db)
    {
        if (db is null)
        {
            return null;
        }

        try
        {
            int gen = db.GetMaxGeneration();
            return gen <= 0 ? null : gen;
        }
        catch
        {
            return null;
        }
    }

    private static IReadOnlyList<string>? ReadOrphans(SentinelDb? db)
    {
        if (db is null)
        {
            return null;
        }

        try
        {
            var rows = db.QueryOrphanDirs(500, 0, out _);
            return rows.Select(r => r.Dir).ToList();
        }
        catch
        {
            return null;
        }
    }

    private static int SafeFlags(SentinelDb db, string path)
    {
        try
        {
            return db.GetFingerprint(path)?.AttrFlags ?? 0;
        }
        catch
        {
            return 0;
        }
    }

    private static string BeforeJson(string path, long size, RiskTier tier) =>
        JsonSerializer.Serialize(new { path, size, tier = tier.ToString() });

    private static string AfterJson(string vaultRef, string vaultPath) =>
        JsonSerializer.Serialize(new { vaultRef, vaultPath });
}
