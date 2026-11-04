namespace Sentinel.Engine.Drivers;

// A driver update candidate from a ladder source: what version, for
// which hardware, signed by whom, and where it came from. Candidates
// carry evidence; eligibility is decided by DriverMatching — never
// by age alone, never without a hardware match.
public sealed record DriverCandidate(
    DriverSource Source,
    string? VendorId,
    string Version,
    string? Date,
    string? Signer,
    IReadOnlyList<string> HardwareIds,
    string? CatalogueId,
    string? LinkUrl);

public sealed record CandidateVerdict(bool Eligible, string Reason);

// D40: hardware/signature/version matching (not age alone).
//   - Hardware: at least one candidate hardware ID must match the
//     device's IDs. An empty candidate list never matches blind.
//   - Signature: a signer must be named (ladder sources sign by
//     construction; a missing signer means broken metadata — reject).
//   - Version: must be NEWER than installed (System.Version numeric
//     compare; unparseable versions fall back to ordinal with the
//     fallback named in the reason).
//   - Blocklist: D42 passes previously-bad versions; blocked
//     candidates are never offered again.
public static class DriverMatching
{
    public static CandidateVerdict CheckEligible(
        DriverCandidate candidate,
        string? installedVersion,
        IReadOnlyList<string> deviceHardwareIds,
        IReadOnlySet<string>? blockedKeys = null)
    {
        if (candidate.HardwareIds.Count == 0)
        {
            return new CandidateVerdict(false,
                "No hardware IDs on the candidate — refusing a blind match.");
        }

        bool hardware = candidate.HardwareIds.Any(c =>
            deviceHardwareIds.Any(d =>
                string.Equals(c, d, StringComparison.OrdinalIgnoreCase)));
        if (!hardware)
        {
            return new CandidateVerdict(false,
                "Hardware IDs do not match this device — not offered.");
        }

        if (string.IsNullOrWhiteSpace(candidate.Signer))
        {
            return new CandidateVerdict(false,
                "No signer named — unsigned or broken metadata is never installed.");
        }

        // D43: WU sometimes reports no version. Without a version
        // there is no newer-check — refusing explicitly beats a
        // misleading "older than installed" from the text fallback.
        if (string.IsNullOrWhiteSpace(candidate.Version))
        {
            return new CandidateVerdict(false,
                "No version reported — installing an unversioned driver is a blind install and is refused.");
        }

        if (blockedKeys is not null && blockedKeys.Contains(BlockKey(candidate)))
        {
            return new CandidateVerdict(false,
                $"Version {candidate.Version} from {candidate.Source} was blocked before (bad or rolled back) — not offered again.");
        }

        int cmp = CompareVersions(candidate.Version, installedVersion, out bool fallback);
        if (cmp <= 0)
        {
            return new CandidateVerdict(false,
                cmp == 0
                    ? $"Already on {candidate.Version} — nothing newer."
                    : $"Candidate {candidate.Version} is older than installed {installedVersion ?? "unknown"} — not offered.");
        }

        return new CandidateVerdict(true,
            $"Newer than installed ({candidate.Version} > {installedVersion ?? "unknown"})" +
            (fallback ? " — compared as text (version did not parse as dotted numbers)." : "."));
    }

    public static string BlockKey(DriverCandidate candidate) =>
        candidate.Source + "|" + (candidate.Version ?? string.Empty);

    // Numeric dotted compare; null sorts below everything; both null
    // equal. Unparseable input falls back to ordinal and says so.
    public static int CompareVersions(string? a, string? b, out bool fallback)
    {
        fallback = false;
        if (a is null && b is null)
        {
            return 0;
        }

        if (a is null)
        {
            return -1;
        }

        if (b is null)
        {
            return 1;
        }

        bool aOk = Version.TryParse(Normalize(a), out var va);
        bool bOk = Version.TryParse(Normalize(b), out var vb);
        if (aOk && bOk)
        {
            return va!.CompareTo(vb!);
        }

        fallback = true;
        return string.Compare(a, b, StringComparison.Ordinal);
    }

    // "05/19/2026 15.11.30.14" (pnputil form) -> "15.11.30.14";
    // already-bare versions pass through.
    public static string Normalize(string version)
    {
        string v = version.Trim();
        int space = v.LastIndexOf(' ');
        if (space >= 0)
        {
            string tail = v.Substring(space + 1);
            if (tail.Any(char.IsDigit))
            {
                return tail;
            }
        }

        return v;
    }
}
