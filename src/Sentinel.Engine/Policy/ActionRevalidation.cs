using Sentinel.Store;

namespace Sentinel.Engine.Policy;

// The scope an approved action was proposed under: scan roots
// plus excluded-from-inspection prefixes. NeverTouch is NOT part
// of this record — it flows through the classifier, which is
// always built fresh from current Settings at revalidation time.
public sealed record ActionScope(
    IReadOnlyList<string> Roots,
    IReadOnlyList<string> ExcludedPrefixes);

public enum ActionRevalidationVerdict
{
    // Live path, in scope, not excluded, not a link, tier
    // unchanged since approval. The ONLY verdict that may proceed.
    Ok,

    // No longer inside the approved scan roots (moved, renamed,
    // or the approval named a different scope).
    OutOfScope,

    // Inside an excluded-from-inspection prefix.
    Excluded,

    // A link at execution time: acting through it would hit an
    // unaudited target. Never followed.
    LinkRefused,

    // Cannot be statted (deleted, locked, access revoked).
    Unreadable,

    // Re-classifies to NEVER under CURRENT rules (added to Never
    // Touch, newly identified system/user data, or was never
    // lawful). Refused even when the approved tier was NEVER —
    // NEVER actions are never proposed.
    Protected,

    // Still actionable, but the tier drifted since approval
    // (aged across a threshold, file changed kind). Needs a fresh
    // Confirm Sheet, not silent execution.
    TierChanged,
}

public sealed record ActionRevalidation(
    ActionRevalidationVerdict Verdict,
    Classification Current,
    string Detail);

// A11: the execution-time re-check every executor must call
// immediately before acting (05 §1.6). The approval-time
// classification is an input, never a shortcut: the file is
// re-resolved, re-scoped, and re-tiered against CURRENT rules.
// Pure except the final live stat. No executor exists yet —
// A04's executor calls this; nothing else may act without it.
public static class ActionRevalidator
{
    public static ActionRevalidation Revalidate(
        string path,
        RiskTier approvedTier,
        RiskClassifier classifier,
        ActionScope scope,
        DateTime utcNow,
        Predicate<string>? isVerifiedOrphan = null,
        // E33: scan-computed attribute flags for this path (dead
        // shortcut, placeholder...). Live stat cannot recompute
        // them; without the lookup the tier may read SAFER than the
        // table showed. Default 0 preserves A11 behavior for callers
        // without inventory access.
        int attrFlags = 0)
    {
        string? full = ScopePaths.CanonicalPath(path);
        if (full is null)
        {
            return new ActionRevalidation(
                ActionRevalidationVerdict.OutOfScope,
                new Classification(RiskTier.Never, ["N-unresolvable"], ["The path cannot be resolved."], null),
                "The path cannot be resolved — nothing will be done.");
        }

        var roots = scope.Roots
            .Select(ScopePaths.CanonicalRoot)
            .Where(r => r is not null)
            .Select(r => r!)
            .ToList();
        if (!roots.Any(r => ScopePaths.IsUnder(full, r)))
        {
            return new ActionRevalidation(
                ActionRevalidationVerdict.OutOfScope,
                new Classification(RiskTier.Never, ["N-outofscope"], ["Outside the approved scan scope."], null),
                "Outside the approved scan scope — nothing will be done.");
        }

        var excluded = scope.ExcludedPrefixes
            .Select(ScopePaths.CanonicalRoot)
            .Where(x => x is not null)
            .Select(x => x!)
            .ToList();
        if (excluded.Any(x => ScopePaths.IsUnder(full, x)))
        {
            return new ActionRevalidation(
                ActionRevalidationVerdict.Excluded,
                new Classification(RiskTier.Never, ["N-excluded"], ["Inside an excluded-from-inspection area."], null),
                "Inside an excluded area — nothing will be done.");
        }

        FileAttributes attr;
        long size;
        long mtime;
        try
        {
            attr = File.GetAttributes(full);
            if ((attr & FileAttributes.ReparsePoint) != 0)
            {
                return new ActionRevalidation(
                    ActionRevalidationVerdict.LinkRefused,
                    new Classification(RiskTier.Never, ["N-link"], ["A link at execution time."], null),
                    "It is a link now — acting through it could hit something else. Nothing will be done.");
            }

            var info = new FileInfo(full);
            size = info.Length;
            mtime = info.LastWriteTimeUtc.Ticks;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new ActionRevalidation(
                ActionRevalidationVerdict.Unreadable,
                new Classification(RiskTier.Never, ["N-unreadable"], ["Cannot be read at execution time."], null),
                $"It cannot be read right now ({ex.GetType().Name}) — nothing will be done.");
        }

        Classification current = classifier.Classify(
            new Fingerprint(full, size, mtime, null, 0, AttrFlags: attrFlags),
            utcNow, isVerifiedOrphan);
        if (current.Tier == RiskTier.Never)
        {
            return new ActionRevalidation(
                ActionRevalidationVerdict.Protected, current,
                "It is protected under current rules (" +
                string.Join(", ", current.Reasons) + ") — nothing will be done.");
        }

        if (current.Tier != approvedTier)
        {
            return new ActionRevalidation(
                ActionRevalidationVerdict.TierChanged, current,
                $"It was approved as {approvedTier} but now reads {current.Tier} — needs a fresh confirmation.");
        }

        return new ActionRevalidation(
            ActionRevalidationVerdict.Ok, current,
            "Re-checked: in scope, unchanged tier, safe to proceed on confirmation.");
    }
}
