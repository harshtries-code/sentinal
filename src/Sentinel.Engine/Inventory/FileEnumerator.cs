namespace Sentinel.Engine.Inventory;

// Explicit stack (never recursion): no stack overflow on deep trees.
// Scope policy, enforced here and nowhere else:
// - A root that is a link is refused (LinkedRootSkipped), never followed.
// - A root that is a plain file is yielded directly.
// - Directory links are recorded as gaps, never descended into.
// - File links are recorded as gaps, never opened (no out-of-scope read).
// - Excluded prefixes (e.g. Sentinel's own data dir) are pruned with
//   one gap per pruned root, so exclusions stay visible, not silent.
internal sealed record DirListing(
    string Dir, int DirectFiles, int DirectSubdirs, int DirectUnverified,
    long MtimeTicks);

internal static class FileEnumerator
{
    public static IEnumerable<string> Enumerate(
        string root,
        List<InventoryGap> gaps,
        CancellationToken ct,
        IReadOnlyList<string>? excludedPrefixes = null,
        List<DirListing>? dirListings = null)
    {
        string fullRoot;
        try
        {
            fullRoot = Path.GetFullPath(root);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            gaps.Add(new InventoryGap(root, "RootInvalid:" + ex.GetType().Name));
            yield break;
        }

        FileAttributes rootAttr;
        try
        {
            rootAttr = File.GetAttributes(fullRoot);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            gaps.Add(new InventoryGap(fullRoot, "RootMissing:" + ex.GetType().Name));
            yield break;
        }

        if ((rootAttr & FileAttributes.ReparsePoint) != 0)
        {
            gaps.Add(new InventoryGap(fullRoot, "LinkedRootSkipped"));
            yield break;
        }

        // A11: canonicalize once per enumeration (not once per
        // directory), through the shared ScopePaths reading.
        var canonicalExcluded = (excludedPrefixes ?? [])
            .Select(ScopePaths.CanonicalRoot)
            .Where(x => x is not null)
            .Select(x => x!)
            .ToList();

        if ((rootAttr & FileAttributes.Directory) == 0)
        {
            // A11: a single-file scan root inside an excluded
            // prefix is refused like any other excluded path.
            if (IsExcluded(fullRoot, canonicalExcluded))
            {
                gaps.Add(new InventoryGap(fullRoot, "ExcludedScope"));
                yield break;
            }

            yield return fullRoot;
            yield break;
        }

        var stack = new Stack<string>();
        stack.Push(fullRoot);
        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var dir = stack.Pop();
            if (IsExcluded(dir, canonicalExcluded))
            {
                gaps.Add(new InventoryGap(dir, "ExcludedScope"));
                continue;
            }

            IEnumerable<string> entries;
            try
            {
                entries = Directory.EnumerateFileSystemEntries(dir);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                gaps.Add(new InventoryGap(dir, ex.GetType().Name));
                continue;
            }

            // P23 census: direct child counts for the empty-chain
            // fold. Recorded only after the listing completes, so a
            // row always means "fully listed". Reparse points,
            // exclusions, and unreadable entries count as UNVERIFIED
            // — never as empty — so a dir holding only a symlink to
            // a live tree can never read as an empty chain.
            int directFiles = 0;
            int directSubdirs = 0;
            int directUnverified = 0;
            foreach (var entry in entries)
            {
                ct.ThrowIfCancellationRequested();
                FileAttributes attr;
                try
                {
                    attr = File.GetAttributes(entry);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    gaps.Add(new InventoryGap(entry, ex.GetType().Name));
                    directUnverified++;
                    continue;
                }

                bool isDir = (attr & FileAttributes.Directory) != 0;
                bool isReparse = (attr & FileAttributes.ReparsePoint) != 0;
                if (isDir)
                {
                    if (isReparse)
                    {
                        gaps.Add(new InventoryGap(entry, "ReparsePointSkipped"));
                        directUnverified++;
                        continue;
                    }

                    if (IsExcluded(entry, canonicalExcluded))
                    {
                        gaps.Add(new InventoryGap(entry, "ExcludedScope"));
                        directUnverified++;
                        continue;
                    }

                    directSubdirs++;
                    stack.Push(entry);
                }
                else if (isReparse)
                {
                    gaps.Add(new InventoryGap(entry, "FileLinkSkipped"));
                    directUnverified++;
                }
                else
                {
                    directFiles++;
                    yield return entry;
                }
            }

            if (dirListings is not null)
            {
                long mtime = 0;
                try
                {
                    mtime = Directory.GetLastWriteTimeUtc(dir).Ticks;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    gaps.Add(new InventoryGap(dir, "DirStatFailed:" + ex.GetType().Name));
                }

                if (mtime != 0)
                {
                    dirListings.Add(new DirListing(
                        dir, directFiles, directSubdirs, directUnverified, mtime));
                }
            }
        }
    }

    private static bool IsExcluded(string path, IReadOnlyList<string> canonicalPrefixes)
    {
        if (canonicalPrefixes.Count == 0)
        {
            return false;
        }

        string? full = ScopePaths.CanonicalPath(path);
        if (full is null)
        {
            return false;
        }

        foreach (var prefix in canonicalPrefixes)
        {
            if (ScopePaths.IsUnder(full, prefix))
            {
                return true;
            }
        }

        return false;
    }
}
