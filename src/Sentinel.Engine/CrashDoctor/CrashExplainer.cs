using System.Text.RegularExpressions;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.Engine.CrashDoctor;

// A citation is an evidence pointer, never prose: a pack entry key
// (BC:/EV:) or a Windows event (log + record ID). Every causal
// claim in a crash answer carries at least one (04 citation test).
public sealed record CrashCitation(
    string Kind,
    string Reference,
    string Label)
{
    public static CrashCitation Pack(string key) => new("pack", key, "Knowledge pack " + key);

    public static CrashCitation Event(string log, long recordId, int eventId) =>
        new("event", $"{log}#{recordId}", $"{log} event {eventId} (record {recordId})");
}

public sealed record CrashFinding(
    string Cause,
    KnowledgePack.Confidence Confidence,
    IReadOnlyList<CrashCitation> Citations);

public sealed record CrashCard(
    string Title,
    string WhatHappened,
    IReadOnlyList<CrashFinding> Findings,
    IReadOnlyList<string> Prevention,
    string Trend,
    IReadOnlyList<string> HonestGaps,
    IReadOnlyList<CrashCitation> EventCitations);

// Deterministic crash explainer (01 §5.5, 02 §10): event records +
// pack entries in, evidence-linked cards out. No model, no guessing:
// unknown codes and modules produce honest gaps. Confidence rises
// ONLY on anchored corroboration (P2-03): a named module, or disk
// warnings whose PROVIDER + DEVICE + TIME all match the crash
// context. Repetition feeds the trend line (frequency), never
// confidence — a dashed relationship is never styled confirmed.
// Never invents a cause.
public static partial class CrashExplainer
{
    public static CrashCard Explain(
        TargetedEventRecord anchor,
        IReadOnlyList<TargetedEventRecord> window)
    {
        var eventCitations = new List<CrashCitation>
        {
            CrashCitation.Event(anchor.Log, anchor.RecordId, anchor.Id),
        };
        var gaps = new List<string>();
        var card = anchor.Provider.Contains("BugCheck", StringComparison.OrdinalIgnoreCase)
                || (anchor.Provider.Contains("WER", StringComparison.OrdinalIgnoreCase) && anchor.Id == 1001)
            ? ExplainBugCheck(anchor, window, eventCitations, gaps)
            : ExplainGenericEvent(anchor, window, eventCitations, gaps);

        return card with { HonestGaps = gaps, EventCitations = eventCitations };
    }

    private static CrashCard ExplainBugCheck(
        TargetedEventRecord anchor,
        IReadOnlyList<TargetedEventRecord> window,
        List<CrashCitation> eventCitations,
        List<string> gaps)
    {
        uint? code = ParseBugCheckCode(anchor);
        string? module = ParseImplicatedModule(anchor);
        string? vendor = module is null ? null : KnowledgePack.FindVendor(module);
        if (module is not null && vendor is null)
        {
            gaps.Add($"Module '{module}' is not in the pack's vendor map.");
        }

        KnowledgePack.PackEntry? pack = code is null ? null : KnowledgePack.FindBugCheck(code.Value);
        if (code is null)
        {
            gaps.Add("No stop code could be read from this BugCheck event.");
        }
        else if (pack is null)
        {
            gaps.Add($"Stop code 0x{code:X} has no pack entry yet —no cause is guessed.");
        }

        // TIME: disk warnings within 24h of the anchor. PROVIDER is
        // enforced inside IsDiskWarning (153/disk, 55/Ntfs — event
        // IDs are provider-scoped, so a foreign 153 is ignored).
        var diskHits = window
            .Where(e => e.RecordId != anchor.RecordId
                && IsDiskWarning(e)
                && Math.Abs((e.TimeUtc - anchor.TimeUtc).TotalHours) <= 24)
            .ToList();
        // DEVICE: a hit corroborates only when its device token is
        // also named by the crash anchor itself, or recurs on the
        // SAME device in another hit (localizes the fault to one
        // device — the pack's own "same disk" rule, EV:disk#153).
        // Anything else is nearby-in-time-only: observed, reported
        // as a gap, never a confidence raise.
        var anchorDevices = ParseDeviceTokens(
            anchor.Message + " " + string.Join(" ", anchor.Properties));
        var hitsByDevice = diskHits
            .Select(h => (Hit: h, Devices: ParseDeviceTokens(
                h.Message + " " + string.Join(" ", h.Properties))))
            .ToList();
        var anchoredHits = hitsByDevice
            .Where(x => x.Devices.Overlaps(anchorDevices)
                || hitsByDevice.Any(y => y.Hit.RecordId != x.Hit.RecordId
                    && y.Devices.Overlaps(x.Devices)
                    && x.Devices.Count > 0))
            .Select(x => x.Hit)
            .ToList();
        if (diskHits.Count > 0 && anchoredHits.Count == 0)
        {
            gaps.Add(
                $"{diskHits.Count} nearby disk warning(s) name no device " +
                "in common with this crash — nearby in time only, not corroborating.");
        }

        int repeats = window.Count(e =>
            e.RecordId != anchor.RecordId && e.Id == anchor.Id
            && e.Provider.Equals(anchor.Provider, StringComparison.OrdinalIgnoreCase)
            && (anchor.TimeUtc - e.TimeUtc).TotalDays is >= 0 and <= 7);

        var findings = new List<CrashFinding>();
        if (pack is not null && code is not null)
        {
            var cite = CrashCitation.Pack(pack.Key);
            var anchorCites = anchoredHits
                .Select(h => CrashCitation.Event(h.Log, h.RecordId, h.Id))
                .ToList();
            foreach (var cause in pack.Causes)
            {
                var confidence = cause.BaseConfidence;
                var cites = new List<CrashCitation> { cite };
                if (module is not null && cause.RaiseWhen.Contains("named", StringComparison.OrdinalIgnoreCase))
                {
                    confidence = Raise(confidence);
                }

                if (anchoredHits.Count > 0 && cause.RaiseWhen.Contains("disk", StringComparison.OrdinalIgnoreCase))
                {
                    confidence = Raise(confidence);
                    cites.AddRange(anchorCites); // the raise cites its evidence.
                }

                // NOTE (P2-03): repetition does NOT raise confidence
                // here. Frequency is reported by the trend line below;
                // promoting a cause needs anchored evidence, not votes.

                string text = cause.Text;
                if (module is not null && vendor is not null)
                {
                    text += $" Implicated module: {module} ({vendor}).";
                }
                else if (module is not null)
                {
                    text += $" Implicated module: {module} (vendor unknown).";
                }

                findings.Add(new CrashFinding(text, confidence, cites));
            }
        }

        string trend = repeats switch
        {
            0 => "First sighting in the last 7 days of this evidence window.",
            1 => "Second sighting in 7 days — worth watching.",
            _ => $"{repeats + 1} sightings in 7 days — getting worse, act on the steps below.",
        };

        return new CrashCard(
            pack?.Title ?? "Blue screen (unknown stop code)",
            pack is null
                ? "Windows bug-checked, but the stop code is unreadable or unknown to pack v1."
                : $"Windows bug-checked: {pack.Title} (0x{code:X}).",
            findings,
            pack?.Prevention ?? ["Record the stop code and check for a pack update."],
            trend,
            gaps,
            eventCitations);
    }

    private static CrashCard ExplainGenericEvent(
        TargetedEventRecord anchor,
        IReadOnlyList<TargetedEventRecord> window,
        List<CrashCitation> eventCitations,
        List<string> gaps)
    {
        var pack = KnowledgePack.FindEvent(anchor.Provider, anchor.Id);
        if (pack is null)
        {
            gaps.Add($"No pack entry for {anchor.Provider} event {anchor.Id} — no cause is guessed.");
        }

        int repeats = window.Count(e =>
            e.RecordId != anchor.RecordId && e.Id == anchor.Id
            && e.Provider.Equals(anchor.Provider, StringComparison.OrdinalIgnoreCase)
            && (anchor.TimeUtc - e.TimeUtc).TotalDays is >= 0 and <= 30);

        // NOTE (P2-03): repetition does NOT raise confidence.
        // Frequency is reported by the trend line; a repeated
        // symptom is not a confirmed cause.
        var findings = new List<CrashFinding>();
        if (pack is not null)
        {
            var cite = CrashCitation.Pack(pack.Key);
            foreach (var cause in pack.Causes)
            {
                findings.Add(new CrashFinding(cause.Text, cause.BaseConfidence, [cite]));
            }
        }

        string trend = repeats switch
        {
            0 => "First sighting in the last 30 days of this evidence window.",
            1 => "Seen twice in 30 days.",
            _ => $"Seen {repeats + 1} times in 30 days — a pattern, not a fluke.",
        };

        return new CrashCard(
            pack?.Title ?? $"{anchor.Provider} event {anchor.Id}",
            pack is null
                ? $"Observed {anchor.Provider} event {anchor.Id}; pack v1 has no entry for it."
                : $"{pack.Title}: {anchor.Message.Trim()}".Trim(),
            findings,
            pack?.Prevention ?? ["No pack steps for this event yet."],
            trend,
            gaps,
            eventCitations);
    }

    private static KnowledgePack.Confidence Raise(KnowledgePack.Confidence confidence) =>
        confidence switch
        {
            KnowledgePack.Confidence.Low => KnowledgePack.Confidence.Medium,
            KnowledgePack.Confidence.Medium => KnowledgePack.Confidence.High,
            _ => KnowledgePack.Confidence.High,
        };

    // PROVIDER anchor: event IDs are provider-scoped. A 153 from
    // anything but the disk provider (or a 55 from anything but
    // NTFS) is a different event and must not corroborate.
    // Public for the Overview relationships panel (same anchored
    // semantics as the explainer — one rule, two surfaces).
    public static bool IsDiskWarning(TargetedEventRecord record) =>
        (record.Id == 153 && record.Provider.Contains("disk", StringComparison.OrdinalIgnoreCase))
        || (record.Id == 55 && record.Provider.Contains("ntfs", StringComparison.OrdinalIgnoreCase));

    // DEVICE anchor: conservative token extraction from event text.
    // Real 153s name "Disk N" / HarddiskN / DRN / \Device\... paths;
    // real 55s name "volume X:". Tokens are uppercased for matching.
    // Anything unrecognized yields NO token (fail-closed: an
    // unparseable device can never anchor a raise).
    public static HashSet<string> ParseDeviceTokens(string text)
    {
        var tokens = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match m in DevicePattern().Matches(text))
        {
            string token = m.Value.ToUpperInvariant();
            if (token.Length is >= 3 and <= 128)
            {
                tokens.Add(token);
                // The full-path match swallows its components (regex
                // matches don't overlap), so re-emit each segment:
                // "\DEVICE\HARDDISK2\DR2" also yields HARDDISK2 + DR2.
                // A terse "DR2" hit then still anchors a verbose one.
                if (token.StartsWith(@"\DEVICE\", StringComparison.Ordinal))
                {
                    foreach (string seg in token[@"\DEVICE\".Length..].Split('\\'))
                    {
                        if (seg.Length >= 2)
                        {
                            tokens.Add(seg);
                        }
                    }
                }
            }
        }

        return tokens;
    }

    [GeneratedRegex(@"Harddisk\d+|\bDR\d+\b|\bDisk\s+\d+|\\Device\\[^\s,;()]+|[Vv]olume\s+[A-Z]:|[A-Z]:\\", RegexOptions.IgnoreCase)]
    private static partial Regex DevicePattern();

    // Event 1001 properties: [code, param1..4, ...] as hex or decimal.
    internal static uint? ParseBugCheckCode(TargetedEventRecord record)
    {
        foreach (string raw in record.Properties)
        {
            string text = raw.Trim();
            if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                && uint.TryParse(text[2..], System.Globalization.NumberStyles.HexNumber, null, out uint hex))
            {
                return hex;
            }

            if (uint.TryParse(text, out uint dec) && dec is > 0 and < 0x1000)
            {
                return dec;
            }
        }

        return null;
    }

    // Faulting/implicated module names surface in 1000/1001 messages
    // ("... nvlddmkm.sys ..."). Conservative: filename + system ext.
    internal static string? ParseImplicatedModule(TargetedEventRecord record)
    {
        string haystack = record.Message + " " + string.Join(" ", record.Properties);
        foreach (Match m in ModulePattern().Matches(haystack))
        {
            string name = m.Value;
            if (name.Contains('.') && name.Length is >= 5 and <= 64)
            {
                return name;
            }
        }

        return null;
    }

    [System.Text.RegularExpressions.GeneratedRegex(@"[A-Za-z0-9_\-]+\.(sys|dll|exe)", System.Text.RegularExpressions.RegexOptions.IgnoreCase)]
    private static partial System.Text.RegularExpressions.Regex ModulePattern();
}

// Test-harness + panel guard (04): flags any causal claim without
// a pack or event citation. Production explainers must never trip it.
public static class CitationValidator
{
    public static IReadOnlyList<string> FindUncited(CrashCard card)
    {
        var uncited = new List<string>();
        for (int i = 0; i < card.Findings.Count; i++)
        {
            if (card.Findings[i].Citations.Count == 0)
            {
                uncited.Add($"finding[{i}]: {card.Findings[i].Cause}");
            }
        }

        return uncited;
    }
}
