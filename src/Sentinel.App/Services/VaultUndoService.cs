using System.IO;
using Sentinel.Engine.Actions;
using Sentinel.Store;

namespace Sentinel.App.Services;

// E35: executes the "restore from Vault" rollback step that 05 §4
// specifies for clean_items_to_vault. Every restore is verified
// (hash) and audited; conflicts restore BESIDE existing data
// (never overwrite); a damaged or missing vault copy refuses with
// its reason and leaves everything untouched.
public sealed class VaultUndoService : IUndoService
{
    private readonly Func<VaultStore> _vaultFactory;
    private readonly IVaultFileIO _io;
    private readonly string _vaultRoot;
    private readonly IActionAuditSink _audit;

    public VaultUndoService(
        Func<VaultStore> vaultFactory, IVaultFileIO io, string vaultRoot, IActionAuditSink audit)
    {
        _vaultFactory = vaultFactory;
        _io = io;
        _vaultRoot = vaultRoot;
        _audit = audit;
    }

    public async Task<IReadOnlyList<UndoItemResult>> RestoreAsync(
        IReadOnlyList<string> vaultRefs, CancellationToken ct)
    {
        await Task.CompletedTask;
        var results = new List<UndoItemResult>();
        var vault = _vaultFactory();

        foreach (string vaultRef in vaultRefs)
        {
            if (ct.IsCancellationRequested)
            {
                results.Add(new UndoItemResult(vaultRef, false,
                    "Cancelled — the vault still holds the bytes.", null));
                continue;
            }

            results.Add(RestoreOne(vault, vaultRef));
        }

        return results;
    }

    private UndoItemResult RestoreOne(VaultStore vault, string vaultRef)
    {
        VaultItem? row;
        try
        {
            row = vault.Get(vaultRef);
        }
        catch (Exception ex)
        {
            return new UndoItemResult(vaultRef, false,
                $"The vault manifest could not be read ({ex.GetType().Name}) — nothing was done.", null);
        }

        if (row is null)
        {
            return new UndoItemResult(vaultRef, false,
                "No vault record for this item — nothing was done.", null);
        }

        if (row.Status != VaultStatus.Quarantined || !row.Verified)
        {
            return new UndoItemResult(vaultRef, false,
                $"Not restorable in its current state ({row.Status}) — nothing was done. " +
                "See History > Vault for what happened to it.", null);
        }

        string vaultPath = Path.Combine(_vaultRoot, row.VolumeLabel, row.VaultRelPath);
        if (!_io.FileExists(vaultPath))
        {
            return new UndoItemResult(vaultRef, false,
                "The vault copy is missing — nothing was done. The manifest record is kept for forensics.", null);
        }

        string vaultHash;
        try
        {
            vaultHash = _io.ComputeSha256(vaultPath);
        }
        catch (Exception ex)
        {
            return new UndoItemResult(vaultRef, false,
                $"The vault copy could not be read ({ex.GetType().Name}) — nothing was done.", null);
        }

        if (!string.Equals(vaultHash, row.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            return new UndoItemResult(vaultRef, false,
                "The vault copy is damaged (hash mismatch) — left untouched. " +
                "Nothing was written to your files.", null);
        }

        string dest = VaultLayout.RestoreConflictPath(row.OriginalPath, _io.FileExists);
        bool conflict = !string.Equals(dest, row.OriginalPath, StringComparison.OrdinalIgnoreCase);
        bool recreatedParent = false;
        string? parent = Path.GetDirectoryName(dest);
        try
        {
            if (!string.IsNullOrEmpty(parent) && !Directory.Exists(parent))
            {
                _io.CreateDirectory(parent);
                recreatedParent = true;
            }
        }
        catch (Exception ex)
        {
            return new UndoItemResult(vaultRef, false,
                $"The destination folder could not be recreated ({ex.GetType().Name}) — nothing was done.", null);
        }

        try
        {
            vault.MarkInterrupted(vaultRef, VaultStatus.InterruptedRestore, "restoring");
        }
        catch (Exception ex)
        {
            return new UndoItemResult(vaultRef, false,
                $"The vault record could not be updated ({ex.GetType().Name}) — nothing was moved.", null);
        }

        try
        {
            _io.MoveFile(vaultPath, dest);
        }
        catch (Exception ex)
        {
            vault.MarkInterrupted(vaultRef, VaultStatus.InterruptedRestore,
                $"Restore move failed ({ex.GetType().Name}) — the vault copy is untouched.");
            return new UndoItemResult(vaultRef, false,
                $"The restore move failed ({ex.GetType().Name}: {ex.Message}) — " +
                "the vault copy is untouched.", null);
        }

        // Verify the restored bytes before flipping the record.
        string restoredHash;
        try
        {
            restoredHash = _io.ComputeSha256(dest);
        }
        catch (Exception ex)
        {
            return FailRestoredUnverified(vault, row, vaultPath, dest,
                $"The restored copy could not be verified ({ex.GetType().Name}).");
        }

        if (!string.Equals(restoredHash, row.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            return FailRestoredUnverified(vault, row, vaultPath, dest,
                "The restored copy failed verification (bytes differ from the vault record).");
        }

        string detail = conflict
            ? $"Restored beside your existing file as '{Path.GetFileName(dest)}' — your data was not overwritten."
            : "Restored to its original place.";
        if (recreatedParent)
        {
            detail += " Its folder had been deleted, so it was recreated.";
        }

        try
        {
            vault.MarkRestored(vaultRef, DateTime.UtcNow.ToString("o"), dest, detail);
        }
        catch (Exception ex)
        {
            detail += $" (WARNING: the bytes are restored but the record flip failed: {ex.GetType().Name}.)";
            return new UndoItemResult(vaultRef, true, detail, dest);
        }

        if (!_audit.TryAppend(new AuditDraft(
                ActionActors.User, "clean_items_to_vault", [],
                row.Sha256, string.Empty, string.Empty,
                "Vault:" + vaultRef, "Undone",
                "[Undo] " + detail + $" Vault {vaultRef} → '{dest}'."),
                out _, out string auditError))
        {
            detail += $" (WARNING: restored, but the restore could not be audited: {auditError}.)";
        }

        return new UndoItemResult(vaultRef, true, detail, dest);
    }

    // The bytes moved but verification failed: move them BACK into
    // the vault (custody first) and say exactly what happened. The
    // user keeps their (possibly changed) file at the path only when
    // the move-back itself fails — and then the detail says so.
    private UndoItemResult FailRestoredUnverified(
        VaultStore vault, VaultItem row, string vaultPath, string dest, string reason)
    {
        try
        {
            _io.MoveFile(dest, vaultPath);
            vault.MarkInterrupted(row.Id, VaultStatus.InterruptedRestore,
                reason + " The copy was moved back into the vault.");
            return new UndoItemResult(row.Id, false,
                reason + " The copy was moved back into the vault untouched.", null);
        }
        catch (Exception ex)
        {
            vault.MarkInterrupted(row.Id, VaultStatus.InterruptedRestore,
                reason + $" The move-back also failed ({ex.GetType().Name}).");
            return new UndoItemResult(row.Id, false,
                reason + $" It could not be moved back either ({ex.GetType().Name}) — " +
                "verify the file at its path before trusting it.", dest);
        }
    }
}
