using System.Globalization;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using Sentinel.Engine.Agent;

namespace Sentinel.Engine.Ask;

// U27: bounded cloud explanations for Ask questions the deterministic
// engine cannot ground. Same transport as the investigation loop
// (MetaApiAdapter: auth, budgets, payload audit, P25 attempt bound)
// but in Q&A shape: no tools offered, Ask instructions, one short
// answer. The panel escalates ONLY guidance-without-action here;
// refusals, AI-off, and grounded answers never touch the cloud.
public interface IAskCloud
{
    bool CanExplain { get; }

    Task<AskCloudResult> ExplainAsync(string question, AskContext context, CancellationToken ct);
}

public sealed record AskCloudResult(string Text, bool Truncated, long SentBytes);

public sealed class AskCloudExplainer : IAskCloud
{
    public const int MaxDigestChars = 6000;
    public const int MaxHistoryChars = 2000;
    public const int MaxDetailChars = 2000;
    public const int MaxFindings = 12;

    public const string AskInstructions =
        "You are Sentinel's read-only PC assistant. Answer the user's question briefly " +
        "(120 words or fewer) using ONLY the provided PC data: the findings digest and the " +
        "recent history. If the data does not cover the question, say so plainly in one " +
        "sentence. Never invent file contents, paths, system states, or events. Plain " +
        "sentences, no markdown tables, no advice to delete, remove, or change anything.";

    private readonly Func<string?> _keyReader;
    private readonly Func<HttpClient> _httpFactory;
    private readonly PayloadLog _payloads;

    public AskCloudExplainer(
        Func<string?> keyReader, Func<HttpClient> httpFactory, PayloadLog payloads)
    {
        _keyReader = keyReader;
        _httpFactory = httpFactory;
        _payloads = payloads;
    }

    public bool CanExplain
    {
        get
        {
            try
            {
                return !string.IsNullOrWhiteSpace(_keyReader());
            }
            catch
            {
                return false;
            }
        }
    }

    public async Task<AskCloudResult> ExplainAsync(
        string question, AskContext context, CancellationToken ct)
    {
        string? key;
        try
        {
            key = _keyReader();
        }
        catch
        {
            key = null;
        }

        if (string.IsNullOrWhiteSpace(key))
        {
            throw new ModelUnavailableException("NoKey");
        }

        string contextJson = BuildContextJson(question, context);
        var budgets = new InvestigationBudgets();
        using var http = _httpFactory();
        var adapter = new MetaApiAdapter(
            key, MetaApiAdapter.DefaultEndpoint, http,
            Array.Empty<IInvestigationTool>(), _payloads, budgets,
            includeSubmitFinding: false, instructions: AskInstructions);
        ModelTurn turn = await adapter.GetNextStepAsync(contextJson, ct).ConfigureAwait(false);
        if (!turn.Finished || turn.Finding is not null || turn.ToolRequest is not null)
        {
            throw new ModelUnavailableException("UnexpectedTurn");
        }

        string text = (turn.Note ?? string.Empty).Trim();
        if (text.Length == 0)
        {
            throw new ModelUnavailableException("EmptyResponse");
        }

        bool truncated = false;
        if (text.Length > MaxDetailChars)
        {
            int cut = text.LastIndexOf(' ', MaxDetailChars - 1);
            text = text[..(cut > 0 ? cut : MaxDetailChars - 1)] + "…[shortened]";
            truncated = true;
        }

        return new AskCloudResult(text, truncated, budgets.Snapshot().TransmittedBytes);
    }

    // Bounded + redacted like every other model-boundary payload.
    // Findings arrive pre-redacted from the context builder; the
    // question is user-typed and redacted here.
    internal static string BuildContextJson(string question, AskContext context)
    {
        string q = SecretRedactor.RedactSecrets(SecretRedactor.RedactUserPrefix(question));
        if (q.Length > AskEngine.MaxQuestionChars)
        {
            q = q[..AskEngine.MaxQuestionChars] + "…[shortened]";
        }

        var findings = new StringBuilder();
        foreach (var f in context.FindingDigests.Take(MaxFindings))
        {
            findings.Append(CultureInfo.InvariantCulture, $"{f.Number}. [{f.Status}] {f.Observation}");
            if (!string.IsNullOrEmpty(f.Citations))
            {
                findings.Append(CultureInfo.InvariantCulture, $" (evidence: {f.Citations})");
            }

            findings.AppendLine();
        }

        string digest = findings.ToString();
        if (digest.Length > MaxDigestChars)
        {
            digest = digest[..MaxDigestChars] + "…[shortened]";
        }

        string history = context.RecentHistory ?? string.Empty;
        if (history.Length > MaxHistoryChars)
        {
            history = history[..MaxHistoryChars] + "…[shortened]";
        }

        return JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["question"] = q,
            ["findings_digest"] = digest,
            ["recent_history"] = history,
        });
    }
}
