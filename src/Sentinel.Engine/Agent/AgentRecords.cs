namespace Sentinel.Engine.Agent;

public enum InvestigationStatus
{
    Investigating,
    Done,
    Unavailable,
    Off,
    Cancelled,
    OverBudget,
    Failed,
}

public enum FindingStatus
{
    Provisional,
    Confirmed,
    Stale,
    Withdrawn,
}

public enum ToolResultStatus
{
    Ok,
    Denied,
    Stale,
    Error,
}

// One model turn carries exactly one action: a tool request, a
// finding draft, or finish. Bounded by construction: the loop, not
// the model, decides how many turns run.
public sealed record ToolCallRequest(
    string ToolName,
    IReadOnlyDictionary<string, string> Args);

public sealed record FindingDraft(
    string Observation,
    string Interpretation,
    IReadOnlyList<string> EvidenceIds,
    string Limitations,
    string SuggestedNextInspection);

public sealed record ModelTurn(
    ToolCallRequest? ToolRequest,
    FindingDraft? Finding,
    bool Finished,
    string? Note);

// Evidence cited by a finding: the opaque ID the model saw, plus
// the identity the broker resolved it to, so reconciliation can
// revalidate without trusting model memory.
public sealed record CitedEvidence(
    string EvidenceId,
    string Path,
    long Size,
    long MTimeUtcTicks);

// A committed finding with its reconciliation state.
public sealed record AgentFinding(
    string Id,
    int Revision,
    FindingStatus Status,
    string Observation,
    string Interpretation,
    IReadOnlyList<CitedEvidence> Evidence,
    string Limitations,
    string SuggestedNextInspection);
