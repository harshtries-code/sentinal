using Microsoft.Win32;

namespace Sentinel.Engine.Policy;

public sealed record UninstallEntry(
    string DisplayName,
    string? InstallLocation,
    string? DisplayIcon,
    string? UninstallString);

public sealed record OrphanVerdict(
    bool IsPossibleLeftover,
    IReadOnlyList<string> Signals);

// Orphan hunter, part 1 (01 §5.2): leftovers of improperly removed
// apps. Detect-only: registry is READ (05 §10.1), nothing is
// deleted, and a verdict is REVIEW-only, never SAFE — the human
// confirms. Conservative by design: any uninstall-entry match, or
// recent activity, means NOT a leftover. Portable apps with no
// uninstall entry are protected by the quiet-days rule while young;
// genuinely abandoned dirs surface after long silence.
public static class OrphanHunter
{
    public const int DefaultQuietDays = 180;

    public static OrphanVerdict Evaluate(
        string dirPath,
        DateTime youngestMtimeUtc,
        DateTime utcNow,
        IReadOnlyList<UninstallEntry> entries,
        int quietDays = DefaultQuietDays)
    {
        if (MatchesAnyEntry(dirPath, entries))
        {
            return new OrphanVerdict(false, ["InstalledApp"]);
        }

        double quiet = (utcNow - youngestMtimeUtc).TotalDays;
        if (quiet < quietDays)
        {
            return new OrphanVerdict(false, ["RecentlyActive"]);
        }

        return new OrphanVerdict(
            true,
            ["NoUninstallEntry", $"Untouched{(int)quiet}d"]);
    }

    public static bool MatchesAnyEntry(string dirPath, IReadOnlyList<UninstallEntry> entries)
    {
        return FindEntry(dirPath, entries) is not null;
    }

    // P22: owning uninstall entry for an inventoried directory, if any.
    // Location matches (entry points at the dir) beat name matches
    // (token overlap) — the caller shows Unknown when neither fires,
    // never a guess (design board 21).
    public static UninstallEntry? FindEntry(string dirPath, IReadOnlyList<UninstallEntry> entries)
    {
        string dir = Norm(dirPath);
        foreach (var entry in entries)
        {
            if (LocationMatches(dir, entry))
            {
                return entry;
            }
        }

        string leaf = Tokenize(Path.GetFileName(dir));
        foreach (var entry in entries)
        {
            if (NameMatches(leaf, entry))
            {
                return entry;
            }
        }

        return null;
    }

    private static bool LocationMatches(string dir, UninstallEntry entry)
    {
        foreach (var raw in new[] { entry.InstallLocation, entry.DisplayIcon, entry.UninstallString })
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            string candidate = Norm(StripArgs(raw));
            if (candidate.Length == 0)
            {
                continue;
            }

            // Either direction: the entry points inside the dir, or
            // the dir sits inside the entry's install location.
            if (Under(candidate, dir) || Under(dir, candidate))
            {
                return true;
            }
        }

        return false;
    }

    private static bool NameMatches(string leaf, UninstallEntry entry)
    {
        string name = Tokenize(entry.DisplayName);
        if (leaf.Length < 4 || name.Length < 4)
        {
            return false;
        }

        return name.Contains(leaf, StringComparison.Ordinal)
            || leaf.Contains(name, StringComparison.Ordinal);
    }

    // "C:\App\uninstall.exe" /S  ->  C:\App\uninstall.exe
    private static string StripArgs(string raw)
    {
        string text = raw.Trim().Trim('"');
        if (text.StartsWith('"'))
        {
            int end = text.IndexOf('"', 1);
            return end > 1 ? text[1..end] : text;
        }

        int space = text.IndexOf(' ');
        string first = space < 0 ? text : text[..space];
        return first.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? first : text;
    }

    // Lowercase alphanumerics only: "OldApp 2.1" == "oldapp 2-1".
    private static string Tokenize(string value)
    {
        var chars = new char[value.Length];
        int n = 0;
        foreach (char c in value)
        {
            if (char.IsLetterOrDigit(c))
            {
                chars[n++] = char.ToLowerInvariant(c);
            }
        }

        return new string(chars, 0, n);
    }

    // Read-only uninstall inventory (HKLM + HKCU, both registry
    // views). System components skipped: they are not apps a user
    // could have "removed improperly".
    public static IReadOnlyList<UninstallEntry> ReadUninstallEntries()
    {
        var entries = new List<UninstallEntry>();
        foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using var root = RegistryKey.OpenBaseKey(hive, view);
                    using var uninstall = root.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                    if (uninstall is null)
                    {
                        continue;
                    }

                    foreach (string sub in uninstall.GetSubKeyNames())
                    {
                        try
                        {
                            using var key = uninstall.OpenSubKey(sub);
                            if (key is null)
                            {
                                continue;
                            }

                            if (Convert.ToInt32(key.GetValue("SystemComponent", 0)) == 1)
                            {
                                continue;
                            }

                            string? display = Convert.ToString(key.GetValue("DisplayName"));
                            if (string.IsNullOrWhiteSpace(display))
                            {
                                continue;
                            }

                            entries.Add(new UninstallEntry(
                                display.Trim(),
                                BlankToNull(Convert.ToString(key.GetValue("InstallLocation"))),
                                BlankToNull(Convert.ToString(key.GetValue("DisplayIcon"))),
                                BlankToNull(Convert.ToString(key.GetValue("UninstallString")))));
                        }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
                        {
                            continue; // One unreadable subkey never fails the read.
                        }
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
                {
                    continue; // One unreadable hive/view never fails the read.
                }
            }
        }

        return entries;
    }

    private static string? BlankToNull(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

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

    private static bool Under(string path, string root) =>
        path.Equals(root, StringComparison.Ordinal)
        || path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal);
}
