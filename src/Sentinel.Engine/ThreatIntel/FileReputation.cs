namespace Sentinel.Engine.ThreatIntel;

// T53: hash-reputation / second-opinion adapter CONTRACT. This
// file defines the shape a future approved service would plug
// into — it performs NO network egress itself.
//
// Boundaries (pinned by test, preserved by DEC-ANALYZER):
// - Requests carry a SHA-256 hash (+ file size for display)
//   ONLY: no path, no name, no content, no sample bytes.
// - No production adapter is wired: `UnavailableReputationAdapter`
//   is the only implementation, and it always answers Unknown
//   with the honest reason. A named destination + policy +
//   lawful registered template must exist before any other
//   implementation is constructed (DEC-ANALYZER stays
//   proposed_not_approved until then).
public sealed record FileReputationRequest(
    string Sha256,
    long? SizeBytes);

public enum FileReputation
{
    // Nothing is known (or nothing could be asked).
    Unknown,

    // The service has seen this hash and calls it benign.
    // Displayed as the SERVICE's opinion, never Sentinel's
    // verdict — Sentinel itself never calls a file safe.
    KnownGood,

    // The service flags this hash. Displayed with the
    // service's detail; remediation still belongs to Defender.
    KnownBad,
}

public sealed record FileReputationResult(
    FileReputation Verdict,
    string Source,
    string Detail);

// The destination a lookup would go to. Name + policy live
// here so a future approval names something concrete.
public sealed record ReputationDestination(
    string Name,
    string PolicySummary);

public interface IFileReputationAdapter
{
    ReputationDestination Destination { get; }

    Task<FileReputationResult> LookupAsync(
        FileReputationRequest request, CancellationToken ct);
}

// The only wired implementation: no destination is approved,
// so every lookup is honestly unavailable. This type exists so
// callers depend on the contract, not on a null.
public sealed class UnavailableReputationAdapter : IFileReputationAdapter
{
    public static string UnavailableDetail { get; } =
        "Second opinion unavailable — no reputation destination is approved " +
        "(DEC-ANALYZER). The hash above was computed locally and sent nowhere.";

    public ReputationDestination Destination { get; } = new(
        "(no approved destination)",
        "Whole-sample upload is out of v1; no second-opinion service is named.");

    public Task<FileReputationResult> LookupAsync(
        FileReputationRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        return Task.FromResult(new FileReputationResult(
            FileReputation.Unknown, Destination.Name, UnavailableDetail));
    }
}
