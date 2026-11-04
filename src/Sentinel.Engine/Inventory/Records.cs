namespace Sentinel.Engine.Inventory;

public sealed record FileRecord(
    string Path,
    long Size,
    DateTime MTimeUtc,
    bool IsPlaceholder,
    string? Hash,
    bool HashComputed);

public sealed record InventoryGap(string Path, string Reason);

public sealed record InventoryResult(
    long RunId,
    int Generation,
    int FilesSeen,
    long BytesSeen,
    int FilesHashed,
    IReadOnlyList<InventoryGap> Gaps,
    TimeSpan Duration);
