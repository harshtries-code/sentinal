namespace Sentinel.Engine;

// A11: one canonical reading of "is this path under this root".
// Enumeration, broker, excerpts, resume, and action revalidation
// all funnel through here, so the spelling of a path (case,
// separators, relative segments, trailing slash) can never
// change its scope verdict.
public static class ScopePaths
{
    // Canonical root form: full path + trailing separator. Null
    // when the path cannot be resolved (garbage in, no verdict out).
    public static string? CanonicalRoot(string root)
    {
        try
        {
            return Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar)
                + Path.DirectorySeparatorChar;
        }
        catch
        {
            return null;
        }
    }

    // Canonical member form: full path, no trailing separator.
    // Null when the path cannot be resolved.
    public static string? CanonicalPath(string path)
    {
        try
        {
            return Path.GetFullPath(path);
        }
        catch
        {
            return null;
        }
    }

    // Both arguments must already be canonical (see above). A path
    // equal to the root itself counts as under it.
    public static bool IsUnder(string canonicalPath, string canonicalRoot)
    {
        return canonicalPath.StartsWith(canonicalRoot, StringComparison.OrdinalIgnoreCase)
            || string.Equals(
                canonicalPath.TrimEnd(Path.DirectorySeparatorChar),
                canonicalRoot.TrimEnd(Path.DirectorySeparatorChar),
                StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsUnderAny(string path, IEnumerable<string> canonicalRoots)
    {
        string? full = CanonicalPath(path);
        if (full is null)
        {
            return false;
        }

        foreach (var root in canonicalRoots)
        {
            if (IsUnder(full, root))
            {
                return true;
            }
        }

        return false;
    }
}
