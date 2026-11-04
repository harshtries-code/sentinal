using Sentinel.Engine.SystemInventory;

namespace Sentinel.Engine.Drivers;

// The previous driver, preserved before any change: which store
// package to reinstall if verification fails. Without this identity
// there is no rollback — and without a rollback, no update.
public sealed record DriverIdentity(
    string DeviceId,
    string? HardwareId,
    string PublishedInf,
    string? OriginalInf,
    string? Version,
    string? Date,
    string? Signer,
    string? Provider);

public static class DeviceNodeFlags
{
    // DN_NEED_RESTART (cfgmgr32): the device waits on a reboot.
    public const uint NeedRestart = 0x00000200;

    public static bool NeedsRestart(uint status) => (status & NeedRestart) != 0;
}

// D41: links a live installed-driver row (WMI) to its driver-store
// package (pnputil). The WMI signer is usually the WHCP publisher,
// not the vendor — so matching runs on VERSION + DATE, with provider
// containment as a tiebreak only. No match, or an unbreakable tie,
// refuses with its reason: updating without a known previous package
// means updating without a rollback, which 05 forbids.
public static class DriverIdentityCapture
{
    public static (DriverIdentity? Identity, string? Failure) MatchStorePackage(
        string deviceId,
        string? hardwareId,
        DriverRecord installed,
        IReadOnlyList<StorePackage> store)
    {
        var matches = store
            .Where(p => VersionMatches(p.Version, installed.DriverVersion) &&
                DateMatches(p.Version, installed.DriverDate))
            .ToList();

        if (matches.Count == 0)
        {
            return (null,
                "No driver-store package matches the installed driver " +
                $"(version '{installed.DriverVersion ?? "unknown"}', date '{installed.DriverDate ?? "unknown"}') — " +
                "refusing without a known rollback target.");
        }

        StorePackage? pick = matches.Count == 1
            ? matches[0]
            : BreakTie(matches, installed);
        if (pick is null)
        {
            return (null,
                $"Multiple store packages ({string.Join(", ", matches.Select(m => m.PublishedName))}) " +
                "match the installed driver — refusing an ambiguous rollback target.");
        }

        return (new DriverIdentity(
            deviceId, hardwareId, pick.PublishedName, pick.OriginalName,
            pick.Version, installed.DriverDate, pick.Signer, pick.Provider), null);
    }

    private static StorePackage? BreakTie(List<StorePackage> matches, DriverRecord installed)
    {
        var narrowed = matches
            .Where(p => ProviderHinted(p.Provider, installed.DeviceName))
            .ToList();
        return narrowed.Count == 1 ? narrowed[0] : null;
    }

    // Device names usually name the vendor ("Intel(R) Wi-Fi") — a
    // shared-token hint that breaks version+date ties. Never a match
    // on its own, and silence (no names) never picks blind. Tokens
    // under 3 chars are noise ("R", "6") and never match.
    private static bool ProviderHinted(string? storeProvider, string deviceName)
    {
        if (string.IsNullOrWhiteSpace(storeProvider) || string.IsNullOrWhiteSpace(deviceName))
        {
            return false;
        }

        var storeTokens = Tokens(storeProvider);
        var deviceTokens = Tokens(deviceName);
        return storeTokens.Overlaps(deviceTokens);
    }

    private static HashSet<string> Tokens(string value)
    {
        var tokens = new HashSet<string>(StringComparer.Ordinal);
        int start = -1;
        string upper = value.ToUpperInvariant();
        for (int i = 0; i <= upper.Length; i++)
        {
            bool word = i < upper.Length && (char.IsLetterOrDigit(upper[i]));
            if (word && start < 0)
            {
                start = i;
            }

            if (!word && start >= 0)
            {
                string token = upper.Substring(start, i - start);
                if (token.Length >= 3)
                {
                    tokens.Add(token);
                }

                start = -1;
            }
        }

        return tokens;
    }

    private static bool VersionMatches(string? storeVersion, string? installedVersion)
    {
        if (storeVersion is null || installedVersion is null)
        {
            return false;
        }

        return DriverMatching.CompareVersions(
            DriverMatching.Normalize(storeVersion),
            DriverMatching.Normalize(installedVersion), out _) == 0;
    }

    // pnputil "MM/DD/YYYY version" vs WMI "YYYYMMDDHHMMSS...".
    // Unparseable either side → inconclusive → ignored (version and
    // the tiebreak carry the decision; a date we cannot read must not
    // veto a rollback target by itself).
    private static bool DateMatches(string? storeVersion, string? wmiDate)
    {
        string? a = PnputilDate(storeVersion);
        string? b = WmiDate(wmiDate);
        if (a is null || b is null)
        {
            return true;
        }

        return string.Equals(a, b, StringComparison.Ordinal);
    }

    private static string? PnputilDate(string? storeVersion)
    {
        if (string.IsNullOrWhiteSpace(storeVersion))
        {
            return null;
        }

        string head = storeVersion.Trim().Split(' ')[0];
        var parts = head.Split('/');
        if (parts.Length != 3 ||
            !int.TryParse(parts[0], out int month) ||
            !int.TryParse(parts[1], out int day) ||
            !int.TryParse(parts[2], out int year))
        {
            return null;
        }

        try
        {
            return new DateTime(year, month, day).ToString("yyyyMMdd");
        }
        catch
        {
            return null;
        }
    }

    private static string? WmiDate(string? wmiDate)
    {
        if (string.IsNullOrWhiteSpace(wmiDate) || wmiDate.Length < 8)
        {
            return null;
        }

        string head = wmiDate.Substring(0, 8);
        return head.All(char.IsDigit) ? head : null;
    }
}
