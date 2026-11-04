using Sentinel.Store;

namespace Sentinel.Engine.Policy;

// Deterministic risk-tier classifier (01 Layer 2, 05 §2). Pure:
// fingerprints in, labels out. NEVER rules run FIRST and win over
// everything; the default is NEVER. No I/O, no clock reads inside
// (utcNow is a parameter), safe to run over a whole inventory.
// NOTE: no signer/trust input by design — trust can never UPGRADE
// a tier (01 §4), and everything a signature would protect (OS,
// drivers, live apps) is already NEVER by path. Signer evidence
// stays in the Threats flow (StaticEvidenceCollector), not here.
public sealed class RiskClassifier
{
    public const long LargeFileBytes = 100L * 1024 * 1024;
    public const int LargeFileAgeDays = 180;
    public const int DownloadReviewAgeDays = 90;
    public const int DumpSafeAgeDays = 30;
    public const int UpdateLeftoverSafeAgeDays = 7;
    public const int SetupLogSafeAgeDays = 30;

    private readonly string _windows;
    private readonly string _programFiles;
    private readonly string _programFilesX86;
    private readonly string _programData;
    private readonly string _temp;
    private readonly string _localAppData;
    private readonly string _roamingAppData;
    private readonly string[] _userDataRoots;
    private readonly string[] _neverList;

    public RiskClassifier(string[]? neverList = null)
        : this(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            UserDataRoots(),
            neverList ?? Array.Empty<string>())
    {
    }

    // Testable seam: explicit roots (tests must not depend on the
    // machine's real profile layout).
    internal RiskClassifier(
        string windows, string programFiles, string programFilesX86,
        string programData, string temp, string localAppData,
        string roamingAppData, string[] userDataRoots, string[] neverList)
    {
        _windows = Norm(windows);
        _programFiles = Norm(programFiles);
        _programFilesX86 = Norm(programFilesX86);
        _programData = Norm(programData);
        _temp = Norm(temp);
        _localAppData = Norm(localAppData);
        _roamingAppData = Norm(roamingAppData);
        _userDataRoots = userDataRoots.Select(Norm).ToArray();
        _neverList = neverList.Select(Norm).ToArray();
    }

    // isVerifiedOrphan receives the NORMALIZED file path and answers
    // whether it sits under a caller-verified leftover dir
    // (OrphanHunter verdict, R1b). Verified orphans carve the
    // program-roots NEVER rule into REVIEW — never into SAFE.
    public Classification Classify(
        Fingerprint file, DateTime utcNow, Predicate<string>? isVerifiedOrphan = null)
    {
        string path = Norm(file.Path);
        string earlyName = Path.GetFileName(path);
        double ageDays = (utcNow - new DateTime(file.MTimeUtcTicks, DateTimeKind.Utc)).TotalDays;
        if (ageDays < 0)
        {
            ageDays = 0; // Future mtime (clock skew): treat as brand new.
        }

        // ---- NEVER (constitution first; order inside NEVER is free) ----
        if (UnderAny(path, _neverList))
        {
            return Never(["N-neverlist"], ["On your Never Touch list."]);
        }

        // P28: vendor-owned system areas are never offered for
        // automated deletion, whoever owns the drive. Inspection
        // still reads them when they are in scope (the broker never
        // consults this list) — protection is from action, not sight.
        string? vendorReason = VendorProtected.ReasonFor(path);
        if (vendorReason is not null)
        {
            return Never(["N-vendorprotected"], [vendorReason]);
        }

        // P23: a verified-dead shortcut is REVIEW wherever it sits —
        // dead Start Menu/Desktop links are the canonical
        // bad-uninstall signal. The Never list above stays absolute;
        // nothing else carves a dead link back into NEVER.
        if (IsDeadShortcut(path, file.AttrFlags))
        {
            return Review(
                ["R-deadshortcut"],
                ["A shortcut whose target is gone — confirm the target is really gone before removing it."]);
        }

        if (UnderAny(path, [_windows, _programFiles, _programFilesX86, _programData])
            && !IsSafeSystemCarveout(path, earlyName, ageDays)
            && !(isVerifiedOrphan?.Invoke(path) ?? false))
        {
            return Never(["N-systemroot"], ["Inside a Windows or program folder — live OS/app files."]);
        }

        // Downloads is excluded: age decides REVIEW vs NEVER below.
        if (UnderAny(path, _userDataRoots) && !IsDownloads(path))
        {
            return Never(["N-userdata"], ["Inside your documents, media, desktop, or cloud-synced files."]);
        }

        string name = Path.GetFileName(path);
        if (name.Equals("hiberfil.sys", StringComparison.OrdinalIgnoreCase)
            || name.Equals("pagefile.sys", StringComparison.OrdinalIgnoreCase)
            || name.Equals("swapfile.sys", StringComparison.OrdinalIgnoreCase))
        {
            return Never(["N-systemfile"], ["A Windows system file — reported, never removed."]);
        }

        if (IsBrowserProfileData(path))
        {
            return Never(["N-browserdata"], ["Browser profile data (history, logins, state) — never touched."]);
        }

        if (IsLiveDatabase(path))
        {
            return Never(["N-livedb"], ["A live application database or mailbox — deleting it destroys app data."]);
        }

        if (IsGameSave(path))
        {
            return Never(["N-gamesave"], ["Game saves and settings — deleting them erases progress."]);
        }

        if (IsCrashDump(path) && ageDays < DumpSafeAgeDays)
        {
            return Never(["N-recentdump"], ["A recent crash dump — kept as diagnosis evidence."]);
        }

        // ---- SAFE (known-regenerable; kind beats size: a temp file
        // is SAFE at any size, an old dump is SAFE at any size) ----
        string? safe = SafeRule(path, name, ageDays);
        if (safe is not null)
        {
            bool regrows = safe is "S-thumbcache" or "S-shadercache" or "S-browsercache";
            return new Classification(
                RiskTier.Safe, [safe], [SafeReason(safe)],
                regrows ? "Cache — returns in ~2 days of normal use." : null);
        }

        // ---- REVIEW (human must judge) ----
        if (isVerifiedOrphan?.Invoke(path) == true)
        {
            return Review(["R-orphan"], ["Leftover of a removed app (no uninstall entry, long untouched) — confirm it is really gone."]);
        }

        if (IsRecycleBin(path))
        {
            return Review(["R-recycle"], ["Already in the Recycle Bin — permanent deletion needs your call."]);
        }

        if (IsDownloads(path) && ageDays >= DownloadReviewAgeDays)
        {
            return Review(["R-olddownload"], [$"In Downloads, untouched for {(int)ageDays} days."]);
        }

        if (file.Size >= LargeFileBytes && ageDays >= LargeFileAgeDays)
        {
            return Review(["R-largeold"], [$"Large ({FormatBytes(file.Size)}) and untouched for {(int)ageDays} days."]);
        }

        // ---- Default: unknown = NEVER (05 §2). ----
        return Never(["N-unknown"], ["Not a known-safe location — protected until identified."]);
    }

    // SAFE subdirs inside NEVER roots (checked BEFORE the root
    // rule so they stay reachable). R1b extends this pattern for
    // verified orphan leftovers; nothing else may carve NEVER roots.
    private bool IsSafeSystemCarveout(string path, string name, double ageDays)
    {
        if (Under(path, Join(_windows, @"Temp")))
        {
            return true;
        }

        if (Under(path, Join(_windows, @"SoftwareDistribution\Download")) && ageDays >= UpdateLeftoverSafeAgeDays)
        {
            return true;
        }

        if (name.EndsWith(".pf", StringComparison.OrdinalIgnoreCase) && Under(path, Join(_windows, "Prefetch")))
        {
            return true;
        }

        if (name.EndsWith(".log", StringComparison.OrdinalIgnoreCase)
            && Under(path, Join(_windows, "Logs")) && ageDays >= SetupLogSafeAgeDays)
        {
            return true;
        }

        if (IsCrashDump(path) && ageDays >= DumpSafeAgeDays)
        {
            return true;
        }

        return false;
    }

    private string? SafeRule(string path, string name, double ageDays)
    {
        if (Under(path, _temp))
        {
            return "S-temp";
        }

        if (Under(path, Join(_windows, @"Temp")))
        {
            return "S-wintemp";
        }

        if (Under(path, Join(_windows, @"SoftwareDistribution\Download")) && ageDays >= UpdateLeftoverSafeAgeDays)
        {
            return "S-updateleftovers";
        }

        if (name.EndsWith(".pf", StringComparison.OrdinalIgnoreCase)
            && Under(path, Join(_windows, "Prefetch")))
        {
            return "S-prefetch";
        }

        if ((name.StartsWith("thumbcache_", StringComparison.OrdinalIgnoreCase)
                || name.Equals("IconCache.db", StringComparison.OrdinalIgnoreCase))
            && Under(path, Join(_localAppData, @"Microsoft\Windows\Explorer")))
        {
            return "S-thumbcache";
        }

        if (IsShaderCache(path))
        {
            return "S-shadercache";
        }

        if (IsBrowserCache(path))
        {
            return "S-browsercache";
        }

        if (name.EndsWith(".log", StringComparison.OrdinalIgnoreCase)
            && Under(path, Join(_windows, "Logs")) && ageDays >= SetupLogSafeAgeDays)
        {
            return "S-setuplog";
        }

        if (IsCrashDump(path) && ageDays >= DumpSafeAgeDays)
        {
            return "S-olddump";
        }

        if (name.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase) && Under(path, _temp))
        {
            return "S-temp";
        }

        return null;
    }

    private static string SafeReason(string rule) => rule switch
    {
        "S-temp" => "A temp file — Windows and apps recreate these as needed.",
        "S-wintemp" => "A Windows temp file — recreates as needed.",
        "S-updateleftovers" => "An old Windows Update download — superseded packages.",
        "S-prefetch" => "A Prefetch trace — Windows rebuilds it on next launch.",
        "S-thumbcache" => "A thumbnail/icon cache — Explorer rebuilds it.",
        "S-shadercache" => "A GPU shader cache — drivers rebuild it.",
        "S-browsercache" => "A browser web cache — pages re-download as needed.",
        "S-setuplog" => "An old setup log — text history, safe to review away.",
        "S-olddump" => "An old crash dump — past the evidence window.",
        _ => "Known-regenerable.",
    };

    private bool IsBrowserProfileData(string path)
    {
        // Profile data is NEVER unless the specific sub-item is a
        // known cache (05 §2). Cache dirs return false here; the
        // SAFE rule claims them later.
        if (IsBrowserCache(path))
        {
            return false;
        }

        return IsBrowserProfileDir(path);
    }

    private bool IsBrowserProfileDir(string path)
    {
        return Under(path, Join(_localAppData, @"Google\Chrome\User Data"))
            || Under(path, Join(_localAppData, @"Microsoft\Edge\User Data"))
            || Under(path, Join(_localAppData, @"BraveSoftware\Brave-Browser\User Data"))
            || Under(path, Join(_roamingAppData, @"Mozilla\Firefox\Profiles"))
            || Under(path, Join(_roamingAppData, @"Opera Software\Opera Stable"));
    }

    // A06: a "Cache" dir is only a KNOWN browser cache inside a
    // real browser profile. Anywhere else it is unknown content
    // (N-unknown), never a cleanup recommendation.
    private bool IsBrowserCache(string path)
    {
        if (!IsBrowserProfileDir(path))
        {
            return false;
        }

        string[] caches =
        [
            @"\Cache\", @"\Code Cache\", @"\GPUCache\", @"\ShaderCache\",
            @"\cache2\", @"\shader-cache\", @"\Service Worker\CacheStorage\",
        ];
        return caches.Any(c => path.Contains(c, StringComparison.OrdinalIgnoreCase));
    }

    private bool IsShaderCache(string path)
    {
        return Under(path, Join(_localAppData, @"NVIDIA\DXCache"))
            || Under(path, Join(_localAppData, @"NVIDIA\GLCache"))
            || Under(path, Join(_localAppData, @"AMD\DxCache"))
            || Under(path, Join(_localAppData, @"AMD\GLCache"))
            || Under(path, Join(_localAppData, @"D3DSCache"));
    }

    private static bool IsLiveDatabase(string path)
    {
        // Thumbnail/icon caches end in .db but are regenerable caches,
        // claimed by the SAFE rule — not live databases.
        string name = Path.GetFileName(path);
        if (name.StartsWith("thumbcache_", StringComparison.OrdinalIgnoreCase)
            || name.Equals("IconCache.db", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return path.EndsWith(".db", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".sqlite", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".sqlite3", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".mdb", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".pst", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".ost", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsGameSave(string path)
    {
        return path.EndsWith(".sav", StringComparison.OrdinalIgnoreCase)
            || path.Contains(@"\My Games\", StringComparison.OrdinalIgnoreCase)
            || path.Contains(@"\Saved Games\", StringComparison.OrdinalIgnoreCase)
            || path.Contains(@"savegame", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsCrashDump(string path)
    {
        string name = Path.GetFileName(path);
        return name.EndsWith(".dmp", StringComparison.OrdinalIgnoreCase)
            || name.Equals("MEMORY.DMP", StringComparison.OrdinalIgnoreCase);
    }

    private bool IsRecycleBin(string path) =>
        path.Contains(@"$Recycle.Bin\", StringComparison.OrdinalIgnoreCase);

    private static bool IsDeadShortcut(string path, int attrFlags) =>
        (attrFlags & Sentinel.Store.FingerprintAttrs.DeadShortcut) != 0
        && path.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase);

    private bool IsDownloads(string path)
    {
        foreach (var root in _userDataRoots)
        {
            if (root.EndsWith(@"\Downloads", StringComparison.OrdinalIgnoreCase) && Under(path, root))
            {
                return true;
            }
        }

        return false;
    }

    private static Classification Never(string[] rules, string[] reasons) =>
        new(RiskTier.Never, rules, reasons, null);

    private static Classification Review(string[] rules, string[] reasons) =>
        new(RiskTier.Review, rules, reasons, null);

    private static string[] UserDataRoots()
    {
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return
        [
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
            Environment.GetFolderPath(Environment.SpecialFolder.MyMusic),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(profile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.MyVideos),
            Path.Combine(profile, "OneDrive"),
        ];
    }

    private static string Norm(string path) =>
        Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar).ToUpperInvariant();

    private static string Join(string root, string rest) => Norm(Path.Combine(root, rest));

    private static bool Under(string path, string root) =>
        path.Equals(root, StringComparison.Ordinal) || path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal);

    private static bool UnderAny(string path, string[] roots)
    {
        foreach (var root in roots)
        {
            if (root.Length > 0 && Under(path, root))
            {
                return true;
            }
        }

        return false;
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = bytes;
        int unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return $"{value:0.#} {units[unit]}";
    }
}
