namespace Sentinel.Engine.SystemInventory;

public enum CollectionStatus
{
    // Every requested source was read fully.
    Success,

    // Some sources or rows failed; Records holds what was observed.
    Partial,

    // Nothing could be observed; Records is empty by necessity, not by luck.
    Failed,
}

public sealed record CollectionGap(string Source, string Reason, string? Detail = null);

// Every collector returns observations PLUS coverage. Callers must
// branch on Status: an empty Records with Failed/Partial status is
// "could not inspect", never "machine is clean".
public sealed record CollectionResult<T>(
    CollectionStatus Status,
    IReadOnlyList<T> Records,
    string Scope,
    DateTime ObservedUtc,
    IReadOnlyList<CollectionGap> Gaps,
    bool Truncated)
{
    public static CollectionResult<T> Ok(
        IReadOnlyList<T> records, string scope, bool truncated = false)
    {
        return new CollectionResult<T>(
            CollectionStatus.Success, records, scope, DateTime.UtcNow,
            Array.Empty<CollectionGap>(), truncated);
    }

    public static CollectionResult<T> Fail(string scope, string reason, string? detail = null)
    {
        return new CollectionResult<T>(
            CollectionStatus.Failed, Array.Empty<T>(), scope, DateTime.UtcNow,
            [new CollectionGap(scope, reason, detail)], false);
    }
}
