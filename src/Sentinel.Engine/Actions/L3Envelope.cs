using Sentinel.Engine.Policy;
using Sentinel.Store;

namespace Sentinel.Engine.Actions;

// Where an L3 candidate routes. The scheduler (N60) acts on these:
// Auto items dispatch unattended; NeedsConfirm items surface in the
// morning report for one-tap Confirm; Impossible items are skipped
// with their reason. REVIEW can never be Auto; NEVER can never be
// anything but Impossible.
public enum L3Route
{
    Auto,
    NeedsConfirm,
    Impossible,
}

public sealed record L3Candidate(
    string Path,
    RiskTier Tier,
    DateTime? CreatedUtc,
    DateTime ModifiedUtc,
    long SizeBytes,
    bool Locked,
    bool Placeholder);

public sealed record L3Verdict(L3Candidate Candidate, L3Route Route, string Reason);

public sealed record L3Policy(
    bool Enabled,
    PermissionLevel CleanerLevel,
    long MaxBytesPerRun,
    int MaxItemsPerRun,
    TimeSpan MinAge,
    TimeSpan MinUnchanged)
{
    // 05 §3.1 envelope constants.
    public static L3Policy Defaults(bool enabled, PermissionLevel cleanerLevel) => new(
        enabled, cleanerLevel,
        MaxBytesPerRun: 500L * 1024 * 1024,
        MaxItemsPerRun: 5000,
        MinAge: TimeSpan.FromHours(24),
        MinUnchanged: TimeSpan.FromHours(24));
}

public sealed record L3Selection(
    IReadOnlyList<L3Verdict> Eligible,
    IReadOnlyList<L3Verdict> NeedsConfirm,
    IReadOnlyList<L3Verdict> Impossible,
    string? RunRefusedReason);

// E36: the L3 unattended envelope (05 §3.1) as its own tested unit.
// Every condition is re-checked here AND at execution (the envelope
// pre-filters; E31 revalidation is the backstop). Vault-only is
// structural: the only unattended path dispatches clean_items_to_vault
// through the same dispatcher + executor as Confirm. Drivers/Threats
// never reach L3 (capped at L2 by the permission provider).
public static class L3Envelope
{
    public static L3Selection SelectBatch(
        IReadOnlyList<L3Candidate> candidates,
        L3Policy policy,
        DateTime utcNow,
        bool crashEvidenceIn24h)
    {
        string? runRefusal = CheckRun(policy, crashEvidenceIn24h);
        if (runRefusal is not null)
        {
            var blocked = candidates
                .Select(c => new L3Verdict(c, L3Route.Impossible, runRefusal))
                .ToList();
            return new L3Selection([], [], blocked, runRefusal);
        }

        var eligible = new List<L3Verdict>();
        var confirm = new List<L3Verdict>();
        var impossible = new List<L3Verdict>();
        long bytes = 0;

        foreach (var candidate in candidates)
        {
            var verdict = CheckOne(candidate, policy, utcNow);
            switch (verdict.Route)
            {
                case L3Route.NeedsConfirm:
                    confirm.Add(verdict);
                    break;
                case L3Route.Impossible:
                    impossible.Add(verdict);
                    break;
                default:
                    if (eligible.Count >= policy.MaxItemsPerRun ||
                        bytes + candidate.SizeBytes > policy.MaxBytesPerRun)
                    {
                        impossible.Add(new L3Verdict(candidate, L3Route.Impossible,
                            "Run cap reached (5,000 items / 500 MB per run) — carried to the next run."));
                    }
                    else
                    {
                        bytes += candidate.SizeBytes;
                        eligible.Add(verdict);
                    }

                    break;
            }
        }

        return new L3Selection(eligible, confirm, impossible, null);
    }

    // The reference stat block for L3 candidates. The scheduler
    // (N60) MUST build candidates through here — same tier rules,
    // same lock/placeholder probes as the tested path. Missing or
    // unreadable files answer null (skipped, never error).
    public static L3Candidate? Stat(
        string path,
        RiskClassifier classifier,
        DateTime utcNow,
        Predicate<string>? isVerifiedOrphan = null,
        Func<string, int>? attrFlagsLookup = null)
    {
        FileAttributes attr;
        long size;
        long mtime;
        DateTime? created;
        try
        {
            attr = File.GetAttributes(path);
            if ((attr & FileAttributes.Directory) != 0 ||
                (attr & FileAttributes.ReparsePoint) != 0)
            {
                return null;
            }

            var info = new FileInfo(path);
            size = info.Length;
            mtime = info.LastWriteTimeUtc.Ticks;
            created = info.CreationTimeUtc;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        int flags = 0;
        try
        {
            flags = attrFlagsLookup?.Invoke(path) ?? 0;
        }
        catch
        {
            flags = 0;
        }

        var tier = classifier.Classify(
            new Fingerprint(path, size, mtime, null, 0, AttrFlags: flags),
            utcNow, isVerifiedOrphan).Tier;
        return new L3Candidate(
            path, tier, created,
            new DateTime(mtime, DateTimeKind.Utc), size,
            IsLocked(path), FileFlags.IsRecallable(attr));
    }

    private static bool IsLocked(string path)
    {
        try
        {
            using var _ = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None);
            return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return true;
        }
    }

    private static string? CheckRun(L3Policy policy, bool crashEvidenceIn24h)
    {
        // Owner opt-in first: L3 is configured behavior, never assumed.
        if (!policy.Enabled)
        {
            return "L3 auto-clean is off — enable it in Settings to allow unattended cleaning.";
        }

        if (policy.CleanerLevel < PermissionLevel.L3)
        {
            return $"Cleaner permission is L{(int)policy.CleanerLevel} — L3 is required for unattended cleaning.";
        }

        // Any crash in the last 24h blocks the whole run: crash
        // evidence must never be auto-cleaned before diagnosis, and
        // auto-cleaning during crash instability is reckless.
        if (crashEvidenceIn24h)
        {
            return "A crash was recorded in the last 24 hours — unattended cleaning is paused until it is diagnosed.";
        }

        return null;
    }

    private static L3Verdict CheckOne(L3Candidate candidate, L3Policy policy, DateTime utcNow)
    {
        if (candidate.Tier == RiskTier.Never)
        {
            return new L3Verdict(candidate, L3Route.Impossible,
                "Protected — never auto-cleaned under any setting.");
        }

        if (candidate.Tier == RiskTier.Review)
        {
            return new L3Verdict(candidate, L3Route.NeedsConfirm,
                "Needs your confirmation — REVIEW items are never auto-cleaned.");
        }

        if (candidate.Locked)
        {
            return new L3Verdict(candidate, L3Route.Impossible,
                "In use — skipped this run.");
        }

        if (candidate.Placeholder)
        {
            return new L3Verdict(candidate, L3Route.Impossible,
                "Cloud placeholder or offline — skipped this run.");
        }

        if (candidate.CreatedUtc is null)
        {
            return new L3Verdict(candidate, L3Route.Impossible,
                "Age unknown — skipped this run.");
        }

        if (utcNow - candidate.CreatedUtc.Value < policy.MinAge)
        {
            return new L3Verdict(candidate, L3Route.Impossible,
                "Younger than 24 hours — skipped this run.");
        }

        if (utcNow - candidate.ModifiedUtc < policy.MinUnchanged)
        {
            return new L3Verdict(candidate, L3Route.Impossible,
                "Modified in the last 24 hours — skipped this run.");
        }

        return new L3Verdict(candidate, L3Route.Auto,
            "SAFE, old, unchanged, free — eligible for unattended vaulting.");
    }
}
