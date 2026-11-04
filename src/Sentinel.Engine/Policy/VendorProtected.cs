namespace Sentinel.Engine.Policy;

// P28: locations Windows or the OEM owns. These are NEVER offered
// for automated deletion (the classifier tiers them NEVER), but
// they stay INSIDE warranted inspection: the scanner may read
// them for storage accounting and the broker may stat them when
// they are in scope. When they are unreadable they surface as
// STATED gaps ("vendor-protected"), never as silent holes.
//
// Roots are volume-relative ("C:\X" and "D:\X" match alike) and
// matched by exact segment prefix, so "C:\RecoveryX" is NOT
// protected. Case-insensitive; garbage paths never match.
public sealed record VendorProtectedRoot(
    string RelativePath,
    string Name,
    string Reason);

public static class VendorProtected
{
    public static readonly IReadOnlyList<VendorProtectedRoot> Roots =
    [
        new(
            @"\System Volume Information",
            "System Volume Information",
            "Windows shadow copies, restore points and search data live here."),
        new(
            @"\Recovery",
            "Recovery",
            "Windows Recovery Environment files live here."),
        new(
            @"\$WinREAgent",
            "$WinREAgent",
            "Windows update staging for the recovery environment lives here."),
        new(
            @"\Windows\CSC",
            "Offline Files cache",
            "The client-side-caching database lives here."),
    ];

    public static bool IsVendorProtected(string path)
    {
        return ReasonFor(path) is not null;
    }

    public static string? ReasonFor(string path)
    {
        string? full = ScopePaths.CanonicalPath(path);
        if (full is null)
        {
            return null;
        }

        string root;
        try
        {
            root = Path.GetPathRoot(full) ?? string.Empty;
        }
        catch
        {
            return null;
        }

        if (root.Length == 0 || !full.StartsWith(root, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        string relative = full.Substring(root.Length);
        foreach (var entry in Roots)
        {
            string prefix = entry.RelativePath.TrimStart(Path.DirectorySeparatorChar);
            if (relative.Equals(prefix, StringComparison.OrdinalIgnoreCase)
                || relative.StartsWith(prefix + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            {
                return $"Vendor-protected: {entry.Name} — {entry.Reason}";
            }
        }

        return null;
    }
}
