using Sentinel.Engine.Policy;
using Sentinel.Store;

namespace Sentinel.Engine.Actions;

// One file the Confirm Sheet will act on, with the LIVE evidence the
// approval is built from (fingerprint + current tier). The executor
// re-checks all of this at execution time (E31) — the preview is the
// user's view, never the executor's shortcut.
public sealed record CleanPreviewItem(
    string BrokerId,
    string Path,
    string Name,
    long SizeBytes,
    string SizeText,
    long MtimeUtcTicks,
    string ModifiedText,
    RiskTier Tier,
    IReadOnlyList<string> TierReasons);

// One checked entry that will NOT be acted on, with the plain reason
// why. The sheet shows these so "3 of 5 selected" is never a mystery.
public sealed record CleanExcludedItem(string Path, string Reason);

public sealed record CleanPreview(
    IReadOnlyList<CleanPreviewItem> Included,
    IReadOnlyList<CleanExcludedItem> Excluded,
    long TotalBytes,
    string TotalText,
    long Generation,
    IReadOnlyList<string> ScopeRoots,
    DateTimeOffset PreviewedUtc,
    string? RefusedReason);

// E33: builds the exact file list the Confirm Sheet shows. v1 acts
// on FILES only: group rows (orphans, duplicates, apps) and anything
// that is not Safe/Review at preview time is excluded with a named
// reason. Every included item carries a live fingerprint + tier for
// the approval; locks, placeholders, and missing files are excluded
// here AND re-checked at execution.
public static class CleanPreviewBuilder
{
    // Same bound as the L3 run cap (05 §3.1): one preview never
    // names more items than one run may touch.
    public const int MaxPreviewItems = 5000;

    public static CleanPreview BuildPreview(
        IReadOnlyList<(string Path, string Mix)> selection,
        RiskClassifier classifier,
        DateTime utcNow,
        long generation,
        IReadOnlyList<string> scopeRoots,
        Predicate<string>? isVerifiedOrphan = null,
        // Scan-computed attribute flags by path (dead shortcut,
        // placeholder...). Without them a dead shortcut reads SAFE
        // here while the table shows REVIEW — the approval basis
        // must agree with the table, and execution (E31) reads the
        // same lookup, so preview and execution agree too.
        Func<string, int>? attrFlagsLookup = null)
    {
        var previewed = DateTimeOffset.UtcNow;
        if (selection.Count == 0)
        {
            return new CleanPreview([], [], 0, "0 bytes", generation, scopeRoots,
                previewed, "Nothing is selected — select files first.");
        }

        if (selection.Count > MaxPreviewItems)
        {
            return new CleanPreview([], [], 0, "0 bytes", generation, scopeRoots,
                previewed,
                $"Too many items ({selection.Count:N0}) — select at most {MaxPreviewItems:N0} so every file can be listed and re-checked.");
        }

        string brokerPrefix = "ui-" + Guid.NewGuid().ToString("N").Substring(0, 8);
        var included = new List<CleanPreviewItem>();
        var excluded = new List<CleanExcludedItem>();
        int n = 0;
        foreach (var (path, mix) in selection)
        {
            n++;
            string? groupReason = GroupExclusion(mix);
            if (groupReason is not null)
            {
                excluded.Add(new CleanExcludedItem(path, groupReason));
                continue;
            }

            FileAttributes attr;
            long size;
            long mtime;
            try
            {
                attr = File.GetAttributes(path);
                if ((attr & FileAttributes.Directory) != 0)
                {
                    excluded.Add(new CleanExcludedItem(path,
                        "This is a folder — v1 vaults files only. Open it and select the files inside."));
                    continue;
                }

                if ((attr & FileAttributes.ReparsePoint) != 0)
                {
                    excluded.Add(new CleanExcludedItem(path,
                        "This is a link, not a file — acting through it could hit something else."));
                    continue;
                }

                if (FileFlags.IsRecallable(attr))
                {
                    excluded.Add(new CleanExcludedItem(path,
                        "Cloud placeholder or offline file — open it once yourself, then re-select it."));
                    continue;
                }

                var info = new FileInfo(path);
                size = info.Length;
                mtime = info.LastWriteTimeUtc.Ticks;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                excluded.Add(new CleanExcludedItem(path,
                    $"Cannot be read right now ({ex.GetType().Name}) — it may be gone or access was revoked."));
                continue;
            }

            if (IsLocked(path))
            {
                excluded.Add(new CleanExcludedItem(path,
                    "Open in another program — close it and re-select."));
                continue;
            }

            int flags = 0;
            try
            {
                flags = attrFlagsLookup?.Invoke(path) ?? 0;
            }
            catch
            {
                flags = 0;
            }

            Classification current = classifier.Classify(
                new Fingerprint(path, size, mtime, null, 0, AttrFlags: flags),
                utcNow, isVerifiedOrphan);
            if (current.Tier == RiskTier.Never)
            {
                excluded.Add(new CleanExcludedItem(path,
                    "Protected under current rules (" + string.Join("; ", current.Reasons) + ")."));
                continue;
            }

            included.Add(new CleanPreviewItem(
                $"{brokerPrefix}:{n}", path, System.IO.Path.GetFileName(path),
                size, FormatBytes(size), mtime,
                new DateTime(mtime, DateTimeKind.Utc).ToLocalTime().ToString("g"),
                current.Tier, current.Reasons));
        }

        long total = included.Sum(i => i.SizeBytes);
        return new CleanPreview(included, excluded, total, FormatBytes(total),
            generation, scopeRoots, previewed,
            included.Count == 0 ? "None of the selected entries can be vaulted — see the reasons." : null);
    }

    private static string? GroupExclusion(string mix) => mix switch
    {
        "safe" or "review" => null,
        "duplicates" => "Duplicate sets need keeper reasoning before any member can move — not in v1.",
        "orphans" => "Leftover folders vault file-by-file — open the folder and select the files inside.",
        "apps" => "App groups are never vaulted as a unit — uninstall the app, or select stray files directly.",
        "never-touch" => "Protected — never offered for vaulting.",
        _ => $"Selection type '{mix}' is not vaultable in v1.",
    };

    private static bool IsLocked(string path)
    {
        try
        {
            using var _ = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None);
            return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return true;
        }
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024)
        {
            return $"{bytes} bytes";
        }

        double value = bytes;
        string[] units = ["KB", "MB", "GB", "TB"];
        string unit = "bytes";
        foreach (string u in units)
        {
            value /= 1024;
            unit = u;
            if (value < 1024)
            {
                break;
            }
        }

        return $"{value:0.##} {unit}";
    }
}
