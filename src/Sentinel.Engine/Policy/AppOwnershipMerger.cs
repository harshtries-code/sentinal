namespace Sentinel.Engine.Policy;

// Where one owned folder sits in an app's footprint (P23): the
// install location plus each app-data location, or Unknown when no
// known root contains it.
public enum AppLocationKind
{
    Install,
    SharedData,
    LocalData,
    RoamingData,
    Unknown,
}

public sealed record AppLocation(
    AppLocationKind Kind,
    string Directory,
    long Files,
    long Bytes);

// Everything one installed app owns (02 §7 per-app drawer): merged
// across the install dir, ProgramData, Local, and Roaming groups.
// Unknown folders are never merged into an app — each stays its own
// single-location record.
public sealed record AppOwnership(
    string AppName,
    bool Known,
    IReadOnlyList<AppLocation> Locations,
    long TotalFiles,
    long TotalBytes);

// Pure merge over AppGrouper rows: same uninstall entry = same app.
// Kind comes from the caller's root mapping, never a guess.
public static class AppOwnershipMerger
{
    public static IReadOnlyList<AppOwnership> Merge(
        IReadOnlyList<AppGroup> groups,
        IReadOnlyList<(string Root, AppLocationKind Kind)> roots)
    {
        var normRoots = roots
            .Select(r => (Norm(r.Root), r.Kind))
            .Where(r => r.Item1.Length > 0)
            .ToList();

        var byApp = new Dictionary<string, List<AppGroup>>(StringComparer.Ordinal);
        var names = new Dictionary<string, (string Name, bool Known)>(StringComparer.Ordinal);
        foreach (var group in groups)
        {
            string key = group.Known
                ? "app:" + group.AppName.ToUpperInvariant()
                : "dir:" + Norm(group.Directory);
            if (!byApp.TryGetValue(key, out var list))
            {
                list = [];
                byApp[key] = list;
                names[key] = (group.AppName, group.Known);
            }

            list.Add(group);
        }

        var owned = new List<AppOwnership>(byApp.Count);
        foreach (var kv in byApp)
        {
            var locations = kv.Value
                .Select(g => new AppLocation(
                    KindOf(g.Directory, normRoots),
                    g.Directory, g.Files, g.Bytes))
                .OrderBy(l => KindOrder(l.Kind))
                .ThenByDescending(l => l.Bytes)
                .ToList();
            var (name, known) = names[kv.Key];
            owned.Add(new AppOwnership(
                name, known, locations,
                locations.Sum(l => l.Files),
                locations.Sum(l => l.Bytes)));
        }

        return owned.OrderByDescending(o => o.TotalBytes).ToList();
    }

    public static string GuidanceFor(AppLocationKind kind) => kind switch
    {
        AppLocationKind.Install =>
            "Program files — uninstall the app to remove these; deleting by hand breaks it.",
        AppLocationKind.SharedData =>
            "Shared app data — check the app's own cleanup before touching anything here.",
        AppLocationKind.LocalData =>
            "Local app data and caches — per-file rows in the table say what each item is.",
        AppLocationKind.RoamingData =>
            "Roaming app data (settings, profiles) — removing resets the app or signs you out.",
        _ => "Unclaimed folder — no installed app matched; verify before touching.",
    };

    public static string LabelFor(AppLocationKind kind) => kind switch
    {
        AppLocationKind.Install => "Install",
        AppLocationKind.SharedData => "Shared data",
        AppLocationKind.LocalData => "Local data",
        AppLocationKind.RoamingData => "Roaming data",
        _ => "Unknown",
    };

    private static AppLocationKind KindOf(
        string directory, IReadOnlyList<(string Root, AppLocationKind Kind)> roots)
    {
        string norm = Norm(directory);
        foreach (var (root, kind) in roots)
        {
            if (norm.Equals(root, StringComparison.Ordinal)
                || norm.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            {
                return kind;
            }
        }

        return AppLocationKind.Unknown;
    }

    private static int KindOrder(AppLocationKind kind) => kind switch
    {
        AppLocationKind.Install => 0,
        AppLocationKind.SharedData => 1,
        AppLocationKind.LocalData => 2,
        AppLocationKind.RoamingData => 3,
        _ => 4,
    };

    private static string Norm(string path)
    {
        try
        {
            return Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar).ToUpperInvariant();
        }
        catch
        {
            return path.Trim().ToUpperInvariant();
        }
    }
}
