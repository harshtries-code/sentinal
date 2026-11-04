namespace Sentinel.Engine.Scan;

public enum ScanMode
{
    Eco,
    Balanced,
    Turbo,
}

public enum ScanOutcome
{
    Completed,
    RefusedNotIdle,
    RefusedFullscreen,
    RefusedLowPower,
    Cancelled,
    Failed,
}

// Caps come from 05 §6 and are enforced here, not suggested:
// Eco <= 15 idle-only, Balanced slider 10–30, Turbo <= 60.
public sealed class ScanOptions
{
    public ScanOptions(
        ScanMode mode,
        IReadOnlyList<string> roots,
        int balancedCapPercent = 25,
        IReadOnlyList<string>? excludedPathPrefixes = null)
    {
        if (roots.Count == 0)
        {
            throw new ArgumentException("At least one root is required.", nameof(roots));
        }

        if (balancedCapPercent is < 10 or > 30)
        {
            throw new ArgumentOutOfRangeException(
                nameof(balancedCapPercent),
                "Balanced cap is a 10–30 slider (05 §6).");
        }

        Mode = mode;
        Roots = roots;
        BalancedCapPercent = balancedCapPercent;
        ExcludedPathPrefixes = excludedPathPrefixes ?? Array.Empty<string>();
    }

    public ScanMode Mode { get; }

    public IReadOnlyList<string> Roots { get; }

    public int BalancedCapPercent { get; }

    // Subtrees pruned from enumeration with an ExcludedScope gap each.
    // The app passes its own data directory so scans never inventory
    // the live database (self-observation would be unstable by design).
    public IReadOnlyList<string> ExcludedPathPrefixes { get; }

    public int CpuCapPercent => Mode switch
    {
        ScanMode.Eco => 15,
        ScanMode.Balanced => BalancedCapPercent,
        ScanMode.Turbo => 60,
        _ => 15,
    };

    public int MaxParallelism => Mode switch
    {
        ScanMode.Eco => 1,
        ScanMode.Balanced => 2,
        ScanMode.Turbo => 4,
        _ => 1,
    };
}
