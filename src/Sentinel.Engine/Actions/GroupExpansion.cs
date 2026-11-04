using Sentinel.Engine.Policy;
using Sentinel.Store;

namespace Sentinel.Engine.Actions;

// What one group row expanded to: explicit file selections (each
// still classified + listed + revalidated downstream — expansion
// NEVER approves anything) plus sheet-visible notes (keepers that
// stay, whole-group refusals, truncation).
public sealed record ExpandedGroup(
    IReadOnlyList<(string Path, string Mix)> Files,
    IReadOnlyList<CleanExcludedItem> Notes,
    IReadOnlyList<string> KeeperPaths,
    int SetsExpanded,
    bool Truncated);

// D44: group rows (duplicate sets, orphan dirs) become explicit
// file lists for the clean preview. Rules, all fail-closed:
//   - Duplicates: the keeper (same DuplicateComparer inputs as the
//     table, so the sheet agrees with the display) NEVER enters the
//     file list — it rides as a "stays" note with its rationale.
//     An unreadable/missing keeper holds the WHOLE set: the spares
//     may be the only good copies left.
//   - Every spare is stat-verified against its fingerprint row
//     (exact size+mtime, the same bar as execution E31). A changed
//     file left the set — it is excluded, never vaulted as a
//     "duplicate" it no longer is.
//   - Orphans: the DIRECTORY is never vaultable (listed as a note);
//     only inventoried files under it expand, each classified
//     downstream. Nothing uninventoried, nothing wholesale.
//   - Budgets bound every expansion; overflow truncates with a note,
//     never silently.
public static class GroupExpansion
{
    public sealed record DuplicateInputs(
        IReadOnlyList<string> PreferredRoots,
        IReadOnlyList<string>? LastRoots,
        IReadOnlyList<UninstallEntry> Uninstall);

    public static ExpandedGroup ExpandDuplicateSet(
        SentinelDb db,
        string memberPath,
        DuplicateInputs inputs,
        int budget)
    {
        var files = new List<(string Path, string Mix)>();
        var notes = new List<CleanExcludedItem>();
        if (budget <= 0)
        {
            return new ExpandedGroup(files, notes, [], 0, true);
        }

        Fingerprint? anchor;
        try
        {
            anchor = db.GetFingerprint(memberPath);
        }
        catch (Exception ex)
        {
            notes.Add(new CleanExcludedItem(memberPath,
                $"Inventory record unreadable ({ex.GetType().Name}) — re-scan before vaulting."));
            return new ExpandedGroup(files, notes, [], 0, false);
        }

        if (anchor?.Hash is null)
        {
            notes.Add(new CleanExcludedItem(memberPath,
                "No hashed inventory record for this copy — re-scan before vaulting."));
            return new ExpandedGroup(files, notes, [], 0, false);
        }

        IReadOnlyList<Fingerprint> members;
        try
        {
            // Full set up to the member-query cap (1000): keeper
            // reasoning must compare EVERY member. A full page means
            // the set may continue past what we compare — the whole
            // set holds. Budget truncation happens later, per spare,
            // AFTER the keeper is chosen from the full set.
            members = db.QueryDuplicateMembers(anchor.Hash, 1000);
        }
        catch (Exception ex)
        {
            notes.Add(new CleanExcludedItem(memberPath,
                $"Set members unreadable ({ex.GetType().Name}) — nothing from this set moves."));
            return new ExpandedGroup(files, notes, [], 0, false);
        }

        if (members.Count >= 1000)
        {
            notes.Add(new CleanExcludedItem(memberPath,
                "This set has 1000+ copies — too many to compare whole, so nothing from this set " +
                "moves. Open the folders and select files directly."));
            return new ExpandedGroup(files, notes, [], 0, true);
        }

        if (members.Count < 2)
        {
            notes.Add(new CleanExcludedItem(memberPath,
                "Only one copy is on record now — nothing spare to vault."));
            return new ExpandedGroup(files, notes, [], 0, false);
        }

        var comparison = DuplicateComparer.Compare(
            anchor.Hash, anchor.Size, members,
            inputs.PreferredRoots, inputs.LastRoots, inputs.Uninstall);
        var keeper = comparison.CopiesOrdered.FirstOrDefault(c => c.IsKeeper);
        if (keeper is null)
        {
            notes.Add(new CleanExcludedItem(memberPath,
                "No keeper could be reasoned for this set — keeping all copies."));
            return new ExpandedGroup(files, notes, [], 0, false);
        }

        if (!IsLiveFile(keeper.Path))
        {
            notes.Add(new CleanExcludedItem(memberPath,
                $"Keeper '{keeper.Path}' is missing or unreadable — the spare copies may be " +
                "the only good ones left, so nothing from this set moves."));
            return new ExpandedGroup(files, notes, [], 0, false);
        }

        notes.Add(new CleanExcludedItem(keeper.Path,
            $"Keeper — this copy stays ({string.Join("; ", keeper.Reasons)})."));

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { keeper.Path };
        bool truncated = false;
        foreach (var copy in comparison.CopiesOrdered)
        {
            if (copy.IsKeeper || !seen.Add(copy.Path))
            {
                continue;
            }

            var record = members.FirstOrDefault(m =>
                string.Equals(m.Path, copy.Path, StringComparison.OrdinalIgnoreCase));
            if (!StatMatches(record, copy.Path, out string statNote))
            {
                notes.Add(new CleanExcludedItem(copy.Path, statNote));
                continue;
            }

            if (files.Count >= budget)
            {
                truncated = true;
                break;
            }

            files.Add((copy.Path, "review"));
        }

        if (truncated)
        {
            notes.Add(new CleanExcludedItem(memberPath,
                $"Selection budget reached — {files.Count} file(s) listed from this set; narrow the selection for the rest."));
        }

        return new ExpandedGroup(files, notes, [keeper.Path], 1, truncated);
    }

    public static ExpandedGroup ExpandOrphanDir(
        SentinelDb db,
        string dir,
        int budget)
    {
        var files = new List<(string Path, string Mix)>();
        var notes = new List<CleanExcludedItem>();
        if (budget <= 0)
        {
            return new ExpandedGroup(files, notes, [], 0, true);
        }

        // Paged: the inventory query clamps Limit at 1000.
        var rows = new List<Fingerprint>();
        bool truncated = false;
        try
        {
            int offset = 0;
            while (rows.Count <= budget)
            {
                var page = db.QueryInventoryPage(new InventoryQuery(
                    DirPrefixes: [dir], Sort: "name", Limit: 1000, Offset: offset));
                if (page.Rows.Count == 0)
                {
                    break;
                }

                rows.AddRange(page.Rows);
                offset += page.Rows.Count;
                if (page.Rows.Count < 1000)
                {
                    break;
                }
            }

            truncated = rows.Count > budget;
            if (truncated)
            {
                rows.RemoveRange(budget, rows.Count - budget);
            }
        }
        catch (Exception ex)
        {
            notes.Add(new CleanExcludedItem(dir,
                $"Inventoried files unreadable ({ex.GetType().Name}) — nothing from this folder moves."));
            return new ExpandedGroup(files, notes, [], 0, false);
        }

        if (rows.Count == 0)
        {
            notes.Add(new CleanExcludedItem(dir,
                "No inventoried files inside — nothing to vault. (Uninventoried files are never vaulted blind.)"));
            return new ExpandedGroup(files, notes, [], 1, false);
        }

        // The directory itself is listed as a note, never a target:
        // folders are never vaulted as a unit.
        notes.Add(new CleanExcludedItem(dir,
            $"Leftover folder — vaults file-by-file only ({rows.Count} inventoried file(s) listed below)."));
        foreach (var row in rows)
        {
            files.Add((row.Path, "review"));
        }

        if (truncated)
        {
            notes.Add(new CleanExcludedItem(dir,
                $"Selection budget reached — {rows.Count} file(s) listed; narrow the selection for the rest."));
        }

        return new ExpandedGroup(files, notes, [], 1, truncated);
    }

    private static bool IsLiveFile(string path)
    {
        try
        {
            var info = new FileInfo(path);
            return info.Exists && (info.Attributes & FileAttributes.Directory) == 0;
        }
        catch
        {
            return false;
        }
    }

    // Exact size+mtime vs the fingerprint row (the E31 bar). A file
    // that changed since the scan left its duplicate set.
    private static bool StatMatches(Fingerprint? record, string path, out string note)
    {
        note = string.Empty;
        if (record is null)
        {
            note = "Left the duplicate set since the scan (no record) — re-scan to re-verify.";
            return false;
        }

        long size;
        long mtime;
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                note = "Gone since the scan — nothing to vault.";
                return false;
            }

            size = info.Length;
            mtime = info.LastWriteTimeUtc.Ticks;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            note = $"Unreadable right now ({ex.GetType().Name}) — nothing moves blind.";
            return false;
        }

        if (size != record.Size || mtime != record.MTimeUtcTicks)
        {
            note = "Changed since the scan (size or date differs) — re-scan to re-verify it is still a duplicate.";
            return false;
        }

        return true;
    }
}
