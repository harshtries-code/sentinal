using Sentinel.Store;

namespace Sentinel.Engine.Scan;

// A07: one shared reading of "which locations does retained
// history span". Run labels are multi-root ("A;B") for full
// scans and the literal "delta" for path rescans — neither form
// is itself a location, so labels are split and "delta" is
// excluded. Bounded by whatever ListRuns cap the caller used.
public static class ScanScopeLabels
{
    public static IReadOnlyList<string> DistinctRoots(IEnumerable<ScanRunInfo> runs)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var roots = new List<string>();
        foreach (var run in runs)
        {
            string label = run.Root ?? string.Empty;
            foreach (string piece in label.Split(';'))
            {
                string root = piece.Trim();
                if (root.Length == 0
                    || root.Equals("delta", StringComparison.OrdinalIgnoreCase)
                    || !seen.Add(root))
                {
                    continue;
                }

                roots.Add(root);
            }
        }

        return roots;
    }

    public static int CountDistinctRoots(IEnumerable<ScanRunInfo> runs) =>
        DistinctRoots(runs).Count;
}
