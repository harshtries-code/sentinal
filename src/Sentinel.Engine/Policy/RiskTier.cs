namespace Sentinel.Engine.Policy;

// Risk tiers (05 §2). Authority: this Layer 2 engine labels;
// NOTHING upgrades a tier — not the AI (01 §4), not the UI.
// Unknown = NEVER: uncertainty resolves toward protection.
public enum RiskTier
{
    // Known-regenerable, no user data. Selectable; L3-eligible.
    Safe,

    // Probably waste, human must judge. Selectable; never L3.
    Review,

    // Protected by constitution. Shown for information only,
    // never selectable for deletion.
    Never,
}

// One classification: tier + human-readable reasons + the rule
// IDs that fired (audit trail for the History page). Regrowth
// notes feed the 7-day re-alert cooldown (01 §5.2).
public sealed record Classification(
    RiskTier Tier,
    IReadOnlyList<string> RuleIds,
    IReadOnlyList<string> Reasons,
    string? ExpectedRegrowth);
