namespace Sentinel.App.Services;

// One restored vault item: where its bytes ended up and whether the
// post-restore verification passed.
public sealed record UndoItemResult(
    string VaultRef,
    bool Restored,
    string Detail,
    string? RestoredPath);

// Rollback runner for completed clean batches. This is NOT an action
// template — it executes the "restore from Vault" rollback step that
// 05 §4 specifies for clean_items_to_vault. Every restore is
// verified and audited exactly like the move was. Implemented by
// VaultUndoService (E35); the Confirm Sheet (E33) only sees this.
public interface IUndoService
{
    Task<IReadOnlyList<UndoItemResult>> RestoreAsync(
        IReadOnlyList<string> vaultRefs, CancellationToken ct);
}

// E33 placeholder: restore executes rollbacks, which land with the
// clean executor (E35). Until then every restore request fails with
// its reason — unreachable in practice, since no batch can complete
// without an executor to offer Undo from.
public sealed class UnavailableUndoService : IUndoService
{
    public Task<IReadOnlyList<UndoItemResult>> RestoreAsync(
        IReadOnlyList<string> vaultRefs, CancellationToken ct)
    {
        IReadOnlyList<UndoItemResult> results = vaultRefs
            .Select(v => new UndoItemResult(v, false, "Restore is not wired in this build yet.", null))
            .ToList();
        return Task.FromResult(results);
    }
}
