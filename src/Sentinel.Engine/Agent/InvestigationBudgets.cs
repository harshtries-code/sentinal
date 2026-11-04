using System.Text;

namespace Sentinel.Engine.Agent;

public sealed class BudgetExhaustedException : Exception
{
    public BudgetExhaustedException(string what)
        : base(what)
    {
    }
}

// Provider-reported token counts for ONE response (Responses
// usage block). Field names here are Sentinel's; the adapter
// maps the wire shape tolerantly (P2-01).
public sealed record ProviderUsage(
    long InputTokens,
    long OutputTokens,
    long ReasoningTokens,
    long CachedTokens);

// Durable budget state: everything a resume must continue
// WITHOUT silently granting a fresh allowance (10 §3, P2-01).
public sealed record BudgetSnapshot(
    int ToolCalls,
    long EvidenceBytes,
    double ElapsedSeconds,
    long InputTokens,
    long OutputTokens,
    long ReasoningTokens,
    long CachedTokens,
    long TransmittedBytes,
    bool HasProviderUsage);

// Enforced per-investigation caps (03 §5, 10 §3). Exhaustion ends
// the loop with partial results + an explicit continuation offer —
// never a claim of full coverage.
//
// Four quantities are tracked SEPARATELY (P2-01), because they
// answer different questions:
//   EvidenceBytes  — tool-result bytes SELECTED by the broker
//                    (UTF-8). Answers "how much evidence did the
//                    model pull?"
//   TransmittedBytes — request + response bytes on the wire
//                    (UTF-8). Answers "how much crossed the
//                    network?" (context is re-sent every turn).
//   ProviderUsage  — token counts REPORTED BY THE PROVIDER.
//                    The ONLY token truth; scripted/offline runs
//                    have none. Never estimated as bytes/4.
//   EstimatedCostUsd — null unless BOTH provider usage AND
//                    verified per-unit pricing exist. No pricing
//                    on file = "Cost estimate unavailable", never
//                    a fabricated spend meter.
public sealed class InvestigationBudgets
{
    private readonly object _gate = new();
    private DateTime _startedUtc = DateTime.UtcNow;
    private int _toolCalls;
    private long _evidenceBytes;
    private long _transmittedBytes;
    private long _inputTokens;
    private long _outputTokens;
    private long _reasoningTokens;
    private long _cachedTokens;
    private bool _hasProviderUsage;

    public int MaxToolCalls { get; set; } = 40;

    public long MaxEvidenceBytes { get; set; } = 2L * 1024L * 1024L;

    // Cumulative wire backstop: 40 turns x ~200KB worst-case
    // context+tools+response stays well under this; it catches
    // runaway growth, not normal investigations.
    public long MaxTransmittedBytes { get; set; } = 8L * 1024L * 1024L;

    // Per-request backstop at the transport: a single turn that
    // serializes past this is refused, not sent (fail-closed).
    public long MaxRequestBytes { get; set; } = 512L * 1024L;

    public TimeSpan MaxDuration { get; set; } = TimeSpan.FromMinutes(10);

    // Verified unit pricing ($/1M tokens), input and output sides.
    // NULL = no verified pricing on file = cost unknown. Set ONLY
    // from the live account's rate card — never scraped pages.
    public double? VerifiedInputUsdPerMillion { get; set; }

    public double? VerifiedOutputUsdPerMillion { get; set; }

    public int ToolCalls
    {
        get { lock (_gate) { return _toolCalls; } }
    }

    public long EvidenceBytes
    {
        get { lock (_gate) { return _evidenceBytes; } }
    }

    public long TransmittedBytes
    {
        get { lock (_gate) { return _transmittedBytes; } }
    }

    public long InputTokens
    {
        get { lock (_gate) { return _inputTokens; } }
    }

    public long OutputTokens
    {
        get { lock (_gate) { return _outputTokens; } }
    }

    public long ReasoningTokens
    {
        get { lock (_gate) { return _reasoningTokens; } }
    }

    public long CachedTokens
    {
        get { lock (_gate) { return _cachedTokens; } }
    }

    public bool HasProviderUsage
    {
        get { lock (_gate) { return _hasProviderUsage; } }
    }

    public TimeSpan Elapsed => DateTime.UtcNow - _startedUtc;

    // Null unless provider usage AND verified pricing both exist.
    // Billing assumptions (documented, not hidden): cached input
    // at the input rate, reasoning at the output rate.
    public double? EstimatedCostUsd
    {
        get
        {
            lock (_gate)
            {
                if (!_hasProviderUsage
                    || VerifiedInputUsdPerMillion is null
                    || VerifiedOutputUsdPerMillion is null)
                {
                    return null;
                }

                double inputSide = (_inputTokens + _cachedTokens)
                    / 1_000_000.0 * VerifiedInputUsdPerMillion.Value;
                double outputSide = (_outputTokens + _reasoningTokens)
                    / 1_000_000.0 * VerifiedOutputUsdPerMillion.Value;
                return inputSide + outputSide;
            }
        }
    }

    public void ChargeCall()
    {
        lock (_gate)
        {
            CheckLocked();
            _toolCalls++;
            if (_toolCalls > MaxToolCalls)
            {
                throw new BudgetExhaustedException("ToolCalls");
            }
        }
    }

    public void ChargeEvidence(long bytes)
    {
        lock (_gate)
        {
            _evidenceBytes += bytes;
            CheckLocked();
            if (_evidenceBytes > MaxEvidenceBytes)
            {
                throw new BudgetExhaustedException("EvidenceBytes");
            }
        }
    }

    // Single-turn wire guard: refuse (don't truncate, don't send)
    // a request past the per-request backstop.
    public void CheckRequestSize(long bytes)
    {
        lock (_gate)
        {
            if (bytes > MaxRequestBytes)
            {
                throw new BudgetExhaustedException("RequestBytes");
            }
        }
    }

    public void ChargeTransmitted(long bytes)
    {
        lock (_gate)
        {
            _transmittedBytes += bytes;
            CheckLocked();
            if (_transmittedBytes > MaxTransmittedBytes)
            {
                throw new BudgetExhaustedException("TransmittedBytes");
            }
        }
    }

    public void ChargeProviderUsage(ProviderUsage usage)
    {
        lock (_gate)
        {
            _inputTokens += Math.Max(0, usage.InputTokens);
            _outputTokens += Math.Max(0, usage.OutputTokens);
            _reasoningTokens += Math.Max(0, usage.ReasoningTokens);
            _cachedTokens += Math.Max(0, usage.CachedTokens);
            _hasProviderUsage = true;
        }
    }

    public void Check()
    {
        lock (_gate)
        {
            CheckLocked();
        }
    }

    public BudgetSnapshot Snapshot()
    {
        lock (_gate)
        {
            return new BudgetSnapshot(
                _toolCalls, _evidenceBytes,
                (DateTime.UtcNow - _startedUtc).TotalSeconds,
                _inputTokens, _outputTokens, _reasoningTokens,
                _cachedTokens, _transmittedBytes, _hasProviderUsage);
        }
    }

    // Resume continues the SAME budget (10 §3): counts, wire
    // totals, provider tokens, AND elapsed time — a reopened
    // investigation must not get a fresh allowance silently.
    public void Restore(BudgetSnapshot snapshot)
    {
        lock (_gate)
        {
            _toolCalls = Math.Max(0, snapshot.ToolCalls);
            _evidenceBytes = Math.Max(0, snapshot.EvidenceBytes);
            _startedUtc = DateTime.UtcNow
                - TimeSpan.FromSeconds(Math.Max(0, snapshot.ElapsedSeconds));
            _inputTokens = Math.Max(0, snapshot.InputTokens);
            _outputTokens = Math.Max(0, snapshot.OutputTokens);
            _reasoningTokens = Math.Max(0, snapshot.ReasoningTokens);
            _cachedTokens = Math.Max(0, snapshot.CachedTokens);
            _transmittedBytes = Math.Max(0, snapshot.TransmittedBytes);
            _hasProviderUsage = snapshot.HasProviderUsage;
        }
    }

    private void CheckLocked()
    {
        if (DateTime.UtcNow - _startedUtc > MaxDuration)
        {
            throw new BudgetExhaustedException("Duration");
        }
    }
}

public sealed record PayloadEntry(
    long Seq,
    DateTime AtUtc,
    string Kind,
    string Text,
    string Destination,
    string DataClass,
    bool Redacted,
    bool Truncated);

// A05: preview vs attempted send vs response vs outcome, in
// plain words for the inspector. Unknown kinds surface raw so
// a new marker can never hide behind a blank label.
public static class PayloadStages
{
    public static string Label(string kind) => kind switch
    {
        "model-request" => "Preview",
        "meta-request" => "Attempted send",
        "model-response" => "Response",
        "meta-response" => "Response",
        "meta-error" => "Send failed",
        "meta-cancelled" => "Send cancelled",
        _ => kind,
    };
}

public sealed record PayloadHistorySnapshot(
    IReadOnlyList<PayloadEntry> Entries,
    int Evicted,
    int TotalAppended,
    int MaxEntries);

// In-memory capture of every model request/response (key material
// never included). Feeds the Payload Inspector and the bounds tests.
// Session-only: counts persist via checkpoints, full text does not.
// A05: a ring, not a silent drop — past MaxEntries the OLDEST entry
// is evicted so the last actual request is always capturable, and
// Evicted counts exactly how many fell off. Seq is ever-increasing
// so the retained window shows its true position.
public sealed class PayloadLog
{
    public const int MaxEntries = 200;

    private readonly List<PayloadEntry> _entries = new();
    private readonly object _gate = new();
    private long _nextSeq;
    private int _evicted;

    public void Append(string kind, string text)
    {
        Append(kind, text, "this PC", "—", redacted: false, truncated: false);
    }

    public void Append(
        string kind, string text, string destination, string dataClass,
        bool redacted, bool truncated)
    {
        lock (_gate)
        {
            _nextSeq++;
            if (_entries.Count >= MaxEntries)
            {
                _entries.RemoveAt(0);
                _evicted++;
            }

            _entries.Add(new PayloadEntry(
                _nextSeq, DateTime.UtcNow, kind, text,
                destination, dataClass, redacted, truncated));
        }
    }

    public IReadOnlyList<PayloadEntry> Entries
    {
        get { lock (_gate) { return _entries.ToList(); } }
    }

    public int Evicted
    {
        get { lock (_gate) { return _evicted; } }
    }

    public int TotalAppended
    {
        get { lock (_gate) { return (int)Math.Min(_nextSeq, int.MaxValue); } }
    }

    public PayloadHistorySnapshot Snapshot()
    {
        lock (_gate)
        {
            return new PayloadHistorySnapshot(
                _entries.ToList(), _evicted,
                (int)Math.Min(_nextSeq, int.MaxValue), MaxEntries);
        }
    }

    // UTF-8 bytes (P2-01): the wire unit. Char counts undercount
    // every non-ASCII payload.
    public long TotalBytes
    {
        get
        {
            lock (_gate)
            {
                long total = 0;
                foreach (var e in _entries)
                {
                    total += Encoding.UTF8.GetByteCount(e.Text);
                }

                return total;
            }
        }
    }
}
