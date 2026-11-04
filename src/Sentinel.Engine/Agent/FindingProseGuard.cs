using System.Text.RegularExpressions;

namespace Sentinel.Engine.Agent;

// P25: keeps agent findings advisory, never destructive directives.
// The tool surface is structurally read-only, but finding PROSE is
// free model text — without this guard a finding could still tell
// the user to delete evidence ("you should delete these files").
// Both patterns are deliberately NARROW: they match deletion
// DIRECTIVES, not mentions, and NEGATED directives ("do not delete
// the files", "you should not delete this") must NOT match (pinned
// by test). Verbs cover inflections (delete/deleting/deleted) so
// the canonical "I recommend deleting this save" matches. The
// single funnel is AcceptFinding: rejected drafts are never
// persisted, so resume/reconciliation cannot resurrect them.
// Over-blocking costs a dropped finding + an auditable history
// note; under-blocking shows destruction advice to the user — the
// guard errs toward blocking.
public static partial class FindingProseGuard
{
    // Advisory framing (you should / recommend / must / ...) aimed
    // at a deletion-family verb within the same breath. The tempered
    // window refuses to cross not/never, so negated advice passes.
    [GeneratedRegex(
        @"\b(you should|should|recommend(?:s|ed|ing)?|suggest(?:s|ed|ing)?|please|must|need to|have to|try to|consider|advised to)\b(?:(?!\bnot\b|\bnever\b).){0,60}?\b(delet(?:e|ing|ed)|remov(?:e|ing|ed)|eras(?:e|ing|ed)|wip(?:e|ing|ed)|quarantin(?:e|ing|ed)|uninstall(?:ed|ing)?)\b",
        RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex AdvisoryDelete();

    // Bare imperative at file-ish objects ("delete the log files").
    // Base verb forms only, so past-tense mentions ("removed the
    // files") do not match; lookbehinds exempt not/never/n't. The
    // verb list excludes uninstall (not a deletion recommendation);
    // the object list excludes drive/key/entry (not file deletions).
    [GeneratedRegex(
        @"(?<!\bnot\s{0,3})(?<!\bnever\s{0,3})(?<!n't\s{0,3})\b(delete|remove|erase|wipe|quarantine)\b.{0,40}?\b(this|that|these|those|the|it|them)\b.{0,40}?\b(files?|folders?|directory|directories|documents?|data|logs?)\b",
        RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex ImperativeDelete();

    public static bool RecommendsDeletion(string? text)
    {
        return !string.IsNullOrEmpty(text)
            && (AdvisoryDelete().IsMatch(text) || ImperativeDelete().IsMatch(text));
    }

    public static bool DraftRecommendsDeletion(FindingDraft draft)
    {
        return RecommendsDeletion(draft.Observation)
            || RecommendsDeletion(draft.Interpretation)
            || RecommendsDeletion(draft.Limitations)
            || RecommendsDeletion(draft.SuggestedNextInspection);
    }
}
