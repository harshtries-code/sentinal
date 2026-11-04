using Sentinel.Engine.Policy;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.Engine.Actions;

// Extended refusal codes beyond the A11 seam's verdicts. The seam
// verdict stays the primary authority (scope/links/tier); these name
// the execution-time comparisons E31 adds. Every code is a refusal —
// MayProceed is true only when Verdict is Ok AND Extended is null.
public enum ExecutionExtendedCode
{
    None,
    // Size/mtime differ from the approval: the file changed since
    // confirmation. Needs a fresh Confirm Sheet.
    FingerprintChanged,
    // A newer scan generation exists than the approval's.
    GenerationChanged,
    // Signer subject differs from the approved one.
    SignerChanged,
    // Open by another program (exclusive-share probe failed).
    Locked,
    // Cloud-placeholder-only or offline: acting would recall bytes.
    Placeholder,
    // Template needs elevation, which v1 cannot provide.
    ElevationRequired,
}

public sealed record ExecutionRevalidation(
    ActionRevalidationVerdict Verdict,
    ExecutionExtendedCode Extended,
    Classification Current,
    string Detail,
    bool MayProceed);

// Reads the current Authenticode subject for one path. Production
// reuses StaticEvidenceCollector — the ONE trust implementation —
// so execution-time signer checks can never disagree with scans.
public interface ISignerReader
{
    string? ReadSubject(string path);
}

public sealed class StaticEvidenceSignerReader : ISignerReader
{
    public string? ReadSubject(string path)
    {
        var result = StaticEvidenceCollector.CheckFiles([path], maxFiles: 1);
        return result.Records.Count == 0 ? null : result.Records[0].SignerSubject;
    }
}

// E31: execution-time revalidation (05 §1.6). The approval is
// evidence for comparison, never a shortcut: the target is
// re-statted, re-scoped, and re-tiered against CURRENT rules via the
// A11 seam, then compared against the approval's fingerprint,
// generation, and signer, then checked for locks/placeholders and
// elevation. The FIRST failure wins; anything but a full pass refuses
// with a plain-language reason.
public static class ExecutionRevalidator
{
    public static ExecutionRevalidation RevalidateForExecution(
        string resolvedPath,
        ActionTarget target,
        ActionApproval approval,
        ActionTemplate template,
        RiskClassifier classifier,
        DateTime utcNow,
        ISignerReader signerReader,
        long? currentGeneration = null,
        Predicate<string>? isVerifiedOrphan = null,
        Func<string, int>? attrFlagsLookup = null,
        // D41: elevation probe override. Production passes nothing
        // (live process check); tests pin both elevations so the
        // suite is green elevated or not.
        Func<bool>? elevationProbe = null)
    {
        bool elevated = elevationProbe?.Invoke() ?? ElevationPolicy.IsProcessElevated();
        if (!ElevationPolicy.TemplateMayRun(template, elevated, out string elevationReason))
        {
            return new ExecutionRevalidation(
                ActionRevalidationVerdict.Unreadable, ExecutionExtendedCode.ElevationRequired,
                new Classification(RiskTier.Never, ["N-elevation"], ["Needs elevation."], null),
                elevationReason, MayProceed: false);
        }

        FileAttributes attr;
        long size;
        long mtime;
        try
        {
            attr = File.GetAttributes(resolvedPath);
            var info = new FileInfo(resolvedPath);
            size = info.Length;
            mtime = info.LastWriteTimeUtc.Ticks;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new ExecutionRevalidation(
                ActionRevalidationVerdict.Unreadable, ExecutionExtendedCode.None,
                new Classification(RiskTier.Never, ["N-unreadable"], ["Cannot be read at execution time."], null),
                $"It cannot be read right now ({ex.GetType().Name}) — nothing will be done.",
                MayProceed: false);
        }

        if (FileFlags.IsRecallable(attr))
        {
            return new ExecutionRevalidation(
                ActionRevalidationVerdict.Unreadable, ExecutionExtendedCode.Placeholder,
                new Classification(RiskTier.Never, ["N-placeholder"], ["Cloud placeholder or offline file."], null),
                "It is a cloud placeholder or offline file — moving it would download its bytes first. " +
                "Open it once yourself, then re-confirm. Nothing will be done.",
                MayProceed: false);
        }

        if (size != target.ExpectedSize || mtime != target.ExpectedMtimeUtcTicks)
        {
            return new ExecutionRevalidation(
                ActionRevalidationVerdict.TierChanged, ExecutionExtendedCode.FingerprintChanged,
                new Classification(target.ApprovedTier, ["X-changed"], ["Changed since confirmation."], null),
                "It changed since you confirmed (size or modification time differs) — " +
                "please review it again. Nothing will be done.",
                MayProceed: false);
        }

        if (currentGeneration.HasValue && currentGeneration.Value != approval.Generation)
        {
            return new ExecutionRevalidation(
                ActionRevalidationVerdict.TierChanged, ExecutionExtendedCode.GenerationChanged,
                new Classification(target.ApprovedTier, ["X-generation"], ["A newer scan exists."], null),
                "A newer scan ran after this confirmation — please review the items again. " +
                "Nothing will be done.",
                MayProceed: false);
        }

        if (IsInUse(resolvedPath))
        {
            return new ExecutionRevalidation(
                ActionRevalidationVerdict.Unreadable, ExecutionExtendedCode.Locked,
                new Classification(RiskTier.Never, ["N-locked"], ["Open in another program."], null),
                "It is open in another program — close it and re-confirm. Nothing will be done.",
                MayProceed: false);
        }

        var scope = new ActionScope(approval.ScopeRoots, approval.ScopeExcluded);
        int flags = 0;
        try
        {
            flags = attrFlagsLookup?.Invoke(resolvedPath) ?? 0;
        }
        catch
        {
            // A failed flags lookup is "no scan evidence", not a
            // refusal — live stat still protects the target.
            flags = 0;
        }

        ActionRevalidation seam = ActionRevalidator.Revalidate(
            resolvedPath, target.ApprovedTier, classifier, scope, utcNow, isVerifiedOrphan, flags);
        if (seam.Verdict != ActionRevalidationVerdict.Ok)
        {
            return new ExecutionRevalidation(
                seam.Verdict, ExecutionExtendedCode.None, seam.Current, seam.Detail,
                MayProceed: false);
        }

        if (target.ExpectedSigner is not null)
        {
            string? current = SafeReadSubject(signerReader, resolvedPath);
            if (!string.Equals(current, target.ExpectedSigner, StringComparison.Ordinal))
            {
                return new ExecutionRevalidation(
                    ActionRevalidationVerdict.TierChanged, ExecutionExtendedCode.SignerChanged,
                    seam.Current,
                    "Its digital signature changed since confirmation — please review it again. " +
                    "Nothing will be done.",
                    MayProceed: false);
            }
        }

        return new ExecutionRevalidation(
            ActionRevalidationVerdict.Ok, ExecutionExtendedCode.None, seam.Current,
            "Re-checked at execution: in scope, unchanged, expected signature, safe to proceed.",
            MayProceed: true);
    }

    // Exclusive-share read probe: fails when ANY handle holds the
    // file without full sharing — i.e. a program has it open.
    // Directories answer false (the probe targets file moves).
    private static bool IsInUse(string path)
    {
        try
        {
            if ((File.GetAttributes(path) & FileAttributes.Directory) != 0)
            {
                return false;
            }

            using var _ = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None);
            return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return true;
        }
    }

    private static string? SafeReadSubject(ISignerReader reader, string path)
    {
        try
        {
            return reader.ReadSubject(path);
        }
        catch
        {
            // A signer read that throws is "cannot confirm", which is
            // itself a change from a confirmed signature — refuse.
            return null;
        }
    }
}
