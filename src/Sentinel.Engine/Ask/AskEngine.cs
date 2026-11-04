using System.Text.RegularExpressions;
using Sentinel.Engine.CrashDoctor;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.Engine.Ask;

// One evidence chip: short label + mono-ready detail (pack key,
// event record, counts). Never prose, never a claim by itself.
public sealed record AskEvidenceChip(string Label, string Detail);

// The panel's ONE action (02 §14). Only navigation and scan-start
// exist as kinds: fixes, Turbo, and driver actions cannot be
// expressed here — they route through their normal buttons and
// Confirm Sheets. Enforced by the factory, not by convention.
public sealed record AskAction
{
    private AskAction(string kind, string label, string? target, string? rowKey = null)
    {
        Kind = kind;
        Label = label;
        Target = target;
        RowKey = rowKey;
    }

    public string Kind { get; }

    public string Label { get; }

    public string? Target { get; }

    public string? RowKey { get; }

    public static AskAction OpenPage(string page, string label) => new("OpenPage", label, page);

    // U27: OpenPage that also highlights one target row after
    // navigating. The key is page-defined and opaque here (Crashes
    // uses the crash title); unknown keys keep current selection.
    public static AskAction OpenPageWithRow(string page, string label, string rowKey) =>
        new("OpenPage", label, page, rowKey);

    public static AskAction StartBalancedScan() => new("StartBalancedScan", "Start Balanced scan", null);
}

public sealed record AskAnswer(
    string Fact,
    IReadOnlyList<AskEvidenceChip> Evidence,
    AskAction? Action,
    bool IsGeneralGuidance,
    bool Refused,
    string? Detail = null,
    bool FromCloud = false,
    bool AiDisabled = false);

public sealed record ScanSummary(
    int FilesSeen,
    long BytesSeen,
    int Gaps,
    int Generation,
    string Root,
    string Status,
    double DurationSeconds);

public sealed record AskContext(
    ScanSummary? LastScan,
    IReadOnlyList<CrashCard> RecentCrashes,
    DefenderStatusRecord? Defender,
    string PackVersion,
    IReadOnlyList<AskFindingDigest> FindingDigests,
    string RecentHistory);

// U27: one recent agent finding, pre-redacted + pre-truncated by the
// context builder. The cloud explainer grounds answers in these; the
// panel renders them as citation chips. Numbers are 1-based display
// ordinals, stable within one context build.
public sealed record AskFindingDigest(
    int Number, string Status, string Observation, string Citations);

// Deterministic grounded answerer (01 §5.7, 02 §14): intent rules
// over Passport/scan/pack data. Answers ONLY from the context:
// one plain-language fact + evidence chips + at most one action.
// No evidence = labelled "general guidance"; off-topic = refused.
// U27: the panel escalates guidance-without-action to the cloud
// explainer (AskCloudExplainer) when a key exists; this core's
// contract is unchanged.
public static class AskEngine
{
    public const int MaxFactChars = 280;
    public const int MaxQuestionChars = 500;
    public const int MaxChips = 4;

    public static IReadOnlyList<string> SuggestedChips { get; } =
    [
        "What did my last scan find?",
        "What is eating my disk?",
        "Did that crash happen before?",
        "Start a Balanced scan",
    ];

    // U27: intentHint bypasses keyword classification when the
    // caller already knows the intent ("crash" from the Crashes page
    // prefill, with rowKey selecting the card). Unknown hints fall
    // through to normal classification.
    public static AskAnswer Answer(
        string question, AskContext context, string? intentHint = null, string? rowKey = null)
    {
        if (string.Equals(intentHint, "crash", StringComparison.OrdinalIgnoreCase))
        {
            return AnswerForcedCrash(context, rowKey);
        }

        string q = question.Length > MaxQuestionChars
            ? question[..MaxQuestionChars]
            : question;
        string lower = q.ToLowerInvariant();

        if (IsStartScan(lower))
        {
            return new AskAnswer(
                Fact("Ready when you are — a Balanced scan stays under 30% CPU and you can pause it anytime."),
                context.LastScan is null
                    ? []
                    : [new AskEvidenceChip("last scan", $"{context.LastScan.FilesSeen} files · gen {context.LastScan.Generation}")],
                AskAction.StartBalancedScan(),
                context.LastScan is null,
                false);
        }

        if (IsCrash(lower))
        {
            return AnswerCrash(context);
        }

        if (IsThreat(lower))
        {
            return AnswerThreat(lower, context);
        }

        if (IsStorage(lower))
        {
            return AnswerStorage(context);
        }

        if (IsLastScan(lower))
        {
            return AnswerLastScan(context);
        }

        if (IsOffTopic(lower))
        {
            return new AskAnswer(
                "I only know your PC — try one of the suggested questions.",
                [], null, false, true);
        }

        if (IsPcTopic(lower))
        {
            return new AskAnswer(
                Fact("I don't have evidence for that yet — the Crashes, Startup, and Threats pages arriving next will ground more answers."),
                [], null, true, false);
        }

        return new AskAnswer(
            "I only know your PC — try one of the suggested questions.",
            [], null, false, true);
    }

    private static AskAnswer AnswerLastScan(AskContext context)
    {
        if (context.LastScan is null)
        {
            return new AskAnswer(
                "No scan has run yet — pick a folder above and press Scan.",
                [], AskAction.StartBalancedScan(), true, false);
        }

        var s = context.LastScan;
        return new AskAnswer(
            Fact($"Your last scan saw {s.FilesSeen} files ({FormatBytes(s.BytesSeen)}) with {s.Gaps} gaps in {s.DurationSeconds:F1}s."),
            [
                new AskEvidenceChip("generation", "gen " + s.Generation),
                new AskEvidenceChip("root", s.Root),
                new AskEvidenceChip("status", s.Status),
            ],
            AskAction.OpenPage("Storage", "Open Storage"),
            false, false);
    }

    private static AskAnswer AnswerStorage(AskContext context)
    {
        if (context.LastScan is null)
        {
            return new AskAnswer(
                "I need a scan first — pick a folder above and press Scan, then ask again.",
                [], AskAction.StartBalancedScan(), true, false);
        }

        var s = context.LastScan;
        return new AskAnswer(
            Fact($"Your last scan covered {FormatBytes(s.BytesSeen)} in {s.FilesSeen} files; per-folder breakdowns arrive with the Storage page."),
            [
                new AskEvidenceChip("bytes seen", FormatBytes(s.BytesSeen)),
                new AskEvidenceChip("files", s.FilesSeen.ToString()),
                new AskEvidenceChip("generation", "gen " + s.Generation),
            ],
            AskAction.OpenPage("Storage", "Open Storage"),
            false, false);
    }

    private static AskAnswer AnswerCrash(AskContext context)
    {
        if (context.RecentCrashes.Count == 0)
        {
            return new AskAnswer(
                "No crashes in the last 7 days of the System log — nothing to explain.",
                [new AskEvidenceChip("window", "System log · 7 days · 0 crash events")],
                null, false, false);
        }

        var newest = context.RecentCrashes[0];
        return AnswerCrashFor(context, newest, newest.Title);
    }

    // U27: answers about the SELECTED crash (prefill path). rowKey
    // is the crash title; a miss falls back to the newest card and
    // says so. The action always highlights the ANSWERED card, so
    // the answer and the highlight never disagree.
    private static AskAnswer AnswerForcedCrash(AskContext context, string? rowKey)
    {
        if (context.RecentCrashes.Count == 0)
        {
            return new AskAnswer(
                "No crashes in the last 7 days of the System log — nothing to explain.",
                [new AskEvidenceChip("window", "System log · 7 days · 0 crash events")],
                null, false, false);
        }

        var card = context.RecentCrashes.FirstOrDefault(
            c => string.Equals(c.Title, rowKey, StringComparison.Ordinal));
        string prefix = string.Empty;
        if (card is null)
        {
            card = context.RecentCrashes[0];
            prefix = "That one isn't in the last 7 days — newest crash instead: ";
        }

        return AnswerCrashFor(context, card, card.Title, prefix);
    }

    private static AskAnswer AnswerCrashFor(
        AskContext context, CrashCard card, string? rowKey, string prefix = "")
    {
        string cause = card.Findings.Count > 0
            ? card.Findings[0].Cause
            : "recorded, but pack v" + context.PackVersion + " has no entry for it yet";
        var chips = new List<AskEvidenceChip>();
        if (card.Findings.Count > 0)
        {
            foreach (var cite in card.Findings[0].Citations.Take(2))
            {
                chips.Add(new AskEvidenceChip(cite.Kind == "pack" ? "pack" : "event", cite.Reference));
            }
        }

        foreach (var cite in card.EventCitations.Take(2))
        {
            if (chips.Count >= MaxChips)
            {
                break;
            }

            chips.Add(new AskEvidenceChip("event", cite.Reference));
        }

        string confidence = card.Findings.Count > 0 ? $" ({card.Findings[0].Confidence} confidence)" : string.Empty;
        var action = rowKey is null
            ? AskAction.OpenPage("Crashes", "Open Crashes")
            : AskAction.OpenPageWithRow("Crashes", "Open Crashes", rowKey);
        return new AskAnswer(
            Fact(prefix + $"{card.Title}: {cause}{confidence} {card.Trend}"),
            chips, action, false, false);
    }

    private static AskAnswer AnswerThreat(string lower, AskContext context)
    {
        if (lower.Contains("file"))
        {
            return new AskAnswer(
                Fact("Checking a specific file needs the Threats page file flow, which arrives in R4 — I can already tell you Defender's overall state; ask 'is my PC protected?'."),
                [], null, true, false);
        }

        if (context.Defender is null)
        {
            return new AskAnswer(
                Fact("I couldn't read Defender's status right now — it may be managed by another app; the Threats page will explain when it lands."),
                [], null, true, false);
        }

        var d = context.Defender;
        string state = d.RealTimeProtectionEnabled == true
            ? "Real-time protection is on"
            : "Real-time protection looks OFF — open Windows Security";
        string sig = d.SignatureAgeDays is null
            ? "definitions age unknown"
            : $"definitions {d.SignatureAgeDays} days old";
        return new AskAnswer(
            Fact($"{state}; {sig}."),
            [
                new AskEvidenceChip("engine", d.EngineVersion ?? "unknown"),
                new AskEvidenceChip("signatures", d.SignatureVersion ?? "unknown"),
            ],
            AskAction.OpenPage("Threats", "Open Threats"), false, false);
    }

    private static bool IsStartScan(string lower) =>
        (lower.Contains("start") || lower.Contains("run") || lower.Contains("begin") || lower.Contains("launch"))
        && (lower.Contains("scan") || lower.Contains("check"));

    // U27: whole-word stems only — the old substrings matched
    // "change the channel" (hang) and would match "prevent" (event).
    // Bare "restart"/"shutdown" narrowed to symptom phrases (a
    // how-to "how do I restart" is guidance, not a crash). "error"
    // added: Event 1000 IS an application error, and refusing "did
    // I get an error" was worse than the rare misroute.
    private static readonly Regex CrashWord =
        new(@"\bhang\b|\bhangs\b|\bhung\b|\bhanging\b|\bevents?\b", RegexOptions.IgnoreCase);

    private static bool IsCrash(string lower) =>
        lower.Contains("crash") || lower.Contains("blue screen") || lower.Contains("bsod")
        || lower.Contains("unexpected shutdown") || lower.Contains("restart loop")
        || lower.Contains("restarting") || lower.Contains("reboot loop") || lower.Contains("rebooting")
        || lower.Contains("froze") || lower.Contains("frozen") || lower.Contains("freeze")
        || lower.Contains("error")
        || CrashWord.IsMatch(lower);

    private static bool IsThreat(string lower) =>
        lower.Contains("safe") || lower.Contains("virus") || lower.Contains("threat")
        || lower.Contains("defender") || lower.Contains("malware") || lower.Contains("antivirus")
        || lower.Contains("protected") || lower.Contains("protection");

    private static bool IsStorage(string lower) =>
        lower.Contains("disk") || lower.Contains("storage") || lower.Contains("space")
        || lower.Contains("eating") || lower.Contains("full");

    private static bool IsLastScan(string lower) =>
        lower.Contains("last scan") || lower.Contains("scan find") || lower.Contains("scan result")
        || lower.Contains("scan say") || lower.Contains("scan show");

    private static bool IsOffTopic(string lower)
    {
        string[] offTopic =
        [
            "weather", "joke", "poem", "homework", "recipe", "movie", "song",
            "football", "cricket", "politics", "lottery", "girlfriend", "boyfriend",
            // U27: unambiguous knowledge-seeking markers. Deliberately
            // NOT "score" (health-score questions) or "capital"
            // (password questions) — those stay PC-side.
            "translate", "define", "meaning of", "who won", "president",
            "election", "bitcoin",
        ];
        return offTopic.Any(lower.Contains);
    }

    private static bool IsPcTopic(string lower)
    {
        string[] pcWords =
        [
            "pc", "computer", "laptop", "windows", "file", "folder", "slow",
            "fast", "hot", "fan", "battery", "boot", "startup", "driver",
            "memory", "ram", "cpu", "app", "program", "update", "wifi",
        ];
        return pcWords.Any(lower.Contains);
    }

    // U27: public so the panel reuses the same 280-char
    // sentence-boundary truncation for cloud headlines.
    public static string Fact(string text)
    {
        if (text.Length <= MaxFactChars)
        {
            return text;
        }

        int cut = text.LastIndexOf(' ', MaxFactChars - 1);
        return text[..(cut > 0 ? cut : MaxFactChars - 1)] + "…";
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
