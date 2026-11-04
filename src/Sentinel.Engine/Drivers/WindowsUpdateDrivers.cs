using System.Runtime.Versioning;
using System.Text.RegularExpressions;

namespace Sentinel.Engine.Drivers;

// Windows Update driver search + install via the inbox WUAPI COM
// objects (no extra dependencies, no scraping). LIVE ONLY — the VM
// battery, elevated guest.
//
// Honesty rules:
//   - WU does not report driver versions in its search metadata, so a
//     candidate carries a version ONLY when the title itself names
//     one (many vendor titles do). Version-less candidates are
//     returned with an empty version and the executor refuses them —
//     installing an unversioned driver is a blind install.
//   - Title-to-device matching is token overlap on the device name
//     (or a hardware-ID substring). Weak matches are not returned:
//     an unlisted update is "not found", never force-matched.
//   - Install re-searches and requires the catalogue ID to be in the
//     fresh result set — an approval cannot be rebound to a different
//     update between confirm and execution.
[SupportedOSPlatform("windows")]
public static partial class WindowsUpdateDrivers
{
    public static IReadOnlyList<DriverCandidate> Search(
        string? deviceName, IReadOnlyList<string> hardwareIds)
    {
        dynamic session = Activator.CreateInstance(
            Type.GetTypeFromProgID("Microsoft.Update.Session")!)!;
        try
        {
            dynamic searcher = session.CreateUpdateSearcher();
            try
            {
                searcher.Online = true;
                dynamic result = searcher.Search("IsInstalled=0 and Type='Driver'");
                try
                {
                    var found = new List<DriverCandidate>();
                    dynamic updates = result.Updates;
                    int count = (int)updates.Count;
                    for (int i = 0; i < count; i++)
                    {
                        dynamic update = updates[i];
                        string title = (string)update.Title ?? string.Empty;
                        if (!TitleMatchesDevice(title, deviceName, hardwareIds))
                        {
                            continue;
                        }

                        string updateId = (string)update.Identity.UpdateID ?? string.Empty;
                        string version = TitleVersion(title);
                        found.Add(new DriverCandidate(
                            Source: DriverSource.WindowsUpdate,
                            VendorId: null,
                            Version: version,
                            Date: null,
                            Signer: "Windows Update",
                            HardwareIds: hardwareIds,
                            CatalogueId: updateId,
                            LinkUrl: null));
                    }

                    return found;
                }
                finally
                {
                    Release(result);
                }
            }
            finally
            {
                Release(searcher);
            }
        }
        finally
        {
            Release(session);
        }
    }

    public static InstallResult Install(
        string deviceId, string catalogueId, TimeSpan timeout)
    {
        _ = deviceId;
        _ = timeout;
        dynamic session = Activator.CreateInstance(
            Type.GetTypeFromProgID("Microsoft.Update.Session")!)!;
        try
        {
            dynamic searcher = session.CreateUpdateSearcher();
            try
            {
                searcher.Online = true;
                dynamic result = searcher.Search("IsInstalled=0 and Type='Driver'");
                try
                {
                    dynamic updates = result.Updates;
                    dynamic? match = null;
                    int count = (int)updates.Count;
                    for (int i = 0; i < count; i++)
                    {
                        dynamic update = updates[i];
                        string id = (string)update.Identity.UpdateID ?? string.Empty;
                        if (string.Equals(id, catalogueId, StringComparison.OrdinalIgnoreCase))
                        {
                            match = update;
                            break;
                        }
                    }

                    if (match is null)
                    {
                        return new InstallResult(false, false,
                            "Catalogue ID is not in the current search result set — " +
                            "the update changed since approval. Nothing was installed.");
                    }

                    dynamic collection = Activator.CreateInstance(
                        Type.GetTypeFromProgID("Microsoft.Update.UpdateColl")!)!;
                    try
                    {
                        collection.Add(match);
                        dynamic downloader = session.CreateUpdateDownloader();
                        try
                        {
                            downloader.Updates = collection;
                            dynamic dlResult = downloader.Download();
                            try
                            {
                                if ((int)dlResult.ResultCode != 2) // rcSucceeded
                                {
                                    return new InstallResult(false, false,
                                        $"Download failed (result {(int)dlResult.ResultCode}). Nothing was installed.");
                                }
                            }
                            finally
                            {
                                Release(dlResult);
                            }
                        }
                        finally
                        {
                            Release(downloader);
                        }

                        dynamic installer = session.CreateUpdateInstaller();
                        try
                        {
                            installer.Updates = collection;
                            dynamic inResult = installer.Install();
                            try
                            {
                                int code = (int)inResult.ResultCode;
                                bool reboot = (bool)inResult.RebootRequired;
                                return code == 2
                                    ? new InstallResult(true, reboot,
                                        reboot ? "Installed — a reboot is pending to finish."
                                            : "Installed.")
                                    : new InstallResult(false, reboot,
                                        $"Install failed (result {code})." +
                                        (reboot ? " A reboot is pending." : string.Empty));
                            }
                            finally
                            {
                                Release(inResult);
                            }
                        }
                        finally
                        {
                            Release(installer);
                        }
                    }
                    finally
                    {
                        Release(collection);
                    }
                }
                finally
                {
                    Release(result);
                }
            }
            finally
            {
                Release(searcher);
            }
        }
        finally
        {
            Release(session);
        }
    }

    // Two significant shared tokens, or a hardware-ID substring.
    // Single-token overlap ("Intel", "USB") is far too weak.
    internal static bool TitleMatchesDevice(
        string title, string? deviceName, IReadOnlyList<string> hardwareIds)
    {
        if (string.IsNullOrWhiteSpace(title))
        {
            return false;
        }

        foreach (var hwid in hardwareIds)
        {
            if (!string.IsNullOrWhiteSpace(hwid) && hwid.Length >= 8 &&
                title.Contains(hwid, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        if (string.IsNullOrWhiteSpace(deviceName))
        {
            return false;
        }

        var titleTokens = Tokens(title);
        var nameTokens = Tokens(deviceName);
        int shared = nameTokens.Count(t => t.Length >= 3 && titleTokens.Contains(t));
        return shared >= 2;
    }

    private static HashSet<string> Tokens(string s) =>
        TokenSplit().Split(s.ToUpperInvariant())
            .Where(t => t.Length >= 2)
            .ToHashSet(StringComparer.Ordinal);

    // Trailing dotted-number run, e.g. "... Graphics 31.0.101.2121".
    // Empty when the title names no version (refused downstream).
    internal static string TitleVersion(string title)
    {
        var m = TrailingVersion().Match(title ?? string.Empty);
        return m.Success ? m.Value : string.Empty;
    }

    private static void Release(object? comObject)
    {
        if (comObject is not null && System.Runtime.InteropServices.Marshal.IsComObject(comObject))
        {
            System.Runtime.InteropServices.Marshal.ReleaseComObject(comObject);
        }
    }

    [GeneratedRegex("[^A-Z0-9]+")]
    private static partial Regex TokenSplit();

    [GeneratedRegex(@"\d+\.\d+(?:\.\d+){0,3}\s*$")]
    private static partial Regex TrailingVersion();
}
