using Sentinel.Store;

namespace Sentinel.Engine.Policy;

// P22: per-app storage groups over stated inventory. Each immediate
// child of the given program roots is rolled up (files + subtree
// bytes, one honest number each) and matched to its uninstall entry
// when the evidence supports it. Unmatched children are "Unknown" —
// never attributed by guess (design board 21). The roots bound the
// scope; the caller labels it (e.g. program folders + this user's
// app data), so groups never pretend to cover the whole drive.
public sealed record AppGroup(
    string AppName,
    string Directory,
    long Files,
    long Bytes,
    bool Known);

public static class AppGrouper
{
    public static IReadOnlyList<AppGroup> GroupApps(
        SentinelDb db,
        IReadOnlyList<string> roots,
        IReadOnlyList<UninstallEntry> uninstall,
        CancellationToken ct)
    {
        var groups = new List<AppGroup>();
        foreach (var root in roots)
        {
            ct.ThrowIfCancellationRequested();
            string full;
            try
            {
                full = Path.GetFullPath(root);
            }
            catch
            {
                continue;
            }

            foreach (var child in db.QueryChildRollup(full, ct))
            {
                if (!child.IsDir)
                {
                    continue;
                }

                string dir = Path.Combine(full, child.Name);
                var entry = OrphanHunter.FindEntry(dir, uninstall);
                groups.Add(new AppGroup(
                    entry?.DisplayName ?? "Unknown",
                    dir, child.Files, child.Bytes, entry is not null));
            }
        }

        return groups.OrderByDescending(g => g.Bytes).ToList();
    }
}
