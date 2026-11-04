namespace Sentinel.Engine.Agent;

// A11: the scope an investigation was checkpointed under, as one
// comparable string. Roots + excluded-from-inspection prefixes,
// canonicalized, order-insensitive — plus the excerpt policy
// version, so a privacy-policy change also invalidates resumed
// work. NeverTouch is DELIBERATELY absent: protection-from-action
// never changes what an investigation may inspect, so editing
// the Never Touch list must NOT orphan a resumable checkpoint.
public static class ScopeFingerprint
{
    public const int Version = 1;

    public static string Compute(
        IEnumerable<string> roots, IEnumerable<string>? excluded = null)
    {
        static string Norm(string p) =>
            (ScopePaths.CanonicalRoot(p) ?? p).ToUpperInvariant();
        string r = string.Join(";", roots.Select(Norm)
            .OrderBy(x => x, StringComparer.Ordinal));
        string x = string.Join(";", (excluded ?? []).Select(Norm)
            .OrderBy(s => s, StringComparer.Ordinal));
        return $"v{Version}|e{ExcerptTools.PolicyVersion}|r:{r}|x:{x}";
    }
}

// A11: the auto-resume picker rule, kept in the testable Engine
// layer (the App has no test seam). Resume itself re-checks the
// fingerprint; this gate decides whether Resume is even attempted.
public static class ResumeGate
{
    public static bool IsResumable(
        string status, string? storedFingerprint, string currentFingerprint)
    {
        return string.Equals(status, nameof(InvestigationStatus.Investigating), StringComparison.Ordinal)
            && storedFingerprint is not null
            && string.Equals(storedFingerprint, currentFingerprint, StringComparison.Ordinal);
    }
}
