using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace Sentinel.Engine.Agent;

public sealed class ModelUnavailableException : Exception
{
    public ModelUnavailableException(string reason)
        : base(reason)
    {
    }
}

// Everything the model sees in one turn, serialized by ONE shared
// serializer so payload-log bytes are identical for scripted and
// live adapters (bounds tests stay meaningful without network).
public sealed record ModelContext(
    string Goal,
    string ScanLabel,
    int EvidenceRevision,
    bool CollectionComplete,
    string OverviewJson,
    IReadOnlyList<string> ToolDefinitions,
    IReadOnlyList<string> RecentHistory,
    IReadOnlyList<string> RecentToolResults,
    int ToolCallsUsed,
    int ToolCallsMax,
    long EvidenceBytesUsed,
    long EvidenceBytesMax);

public static class ModelContextSerializer
{
    // Payload captures use relaxed escaping so the inspector (and
    // tests) see literal text such as <redacted>. The broker's byte
    // backstop keeps default escaping (conservative counts).
    internal static readonly JsonSerializerOptions Relaxed = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    // THE outbound boundary (P1-04): every field — goal, scan
    // label, history, results — passes the user-prefix check on
    // the finished JSON. "<user>" is JSON-inert, so structure
    // cannot break. Tool args stay opaque file_ids; excerpts are
    // redacted at emission; this catches model-echoed paths.
    public static string Serialize(ModelContext context)
    {
        return SecretRedactor.RedactUserPrefix(
            JsonSerializer.Serialize(context, Relaxed));
    }

    public static string SerializeResult(ToolResult result)
    {
        return JsonSerializer.Serialize(result, Relaxed);
    }
}

public interface IInvestigationModel
{
    string Name { get; }

    Task<ModelTurn> GetNextStepAsync(string contextJson, CancellationToken ct);
}

// Deterministic stand-in for tests and offline demos: plays a
// script of steps, observing the real serialized context each turn.
// An empty script finishes immediately (valid: "nothing to pursue").
public sealed class ScriptedModel : IInvestigationModel
{
    private readonly Queue<Func<string, CancellationToken, ModelTurn>> _steps;

    public ScriptedModel(IEnumerable<Func<string, CancellationToken, ModelTurn>> steps)
    {
        _steps = new Queue<Func<string, CancellationToken, ModelTurn>>(steps);
    }

    public string Name => "scripted";

    public List<string> ContextsSeen { get; } = new();

    public Task<ModelTurn> GetNextStepAsync(string contextJson, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        ContextsSeen.Add(contextJson);
        if (_steps.Count == 0)
        {
            return Task.FromResult(new ModelTurn(null, null, true, "Script exhausted."));
        }

        return Task.FromResult(_steps.Dequeue()(contextJson, ct));
    }
}

// AI disabled / no key / no network: investigation is honestly
// unavailable; local results stand on their own.
public sealed class OfflineModel : IInvestigationModel
{
    private readonly string _reason;

    public OfflineModel(string reason = "NoKey")
    {
        _reason = reason;
    }

    public string Name => "offline";

    public Task<ModelTurn> GetNextStepAsync(string contextJson, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        throw new ModelUnavailableException(_reason);
    }
}

public sealed class ThrowingModel : IInvestigationModel
{
    private readonly Exception _fault;

    public ThrowingModel(Exception fault)
    {
        _fault = fault;
    }

    public string Name => "throwing-test-double";

    public Task<ModelTurn> GetNextStepAsync(string contextJson, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        throw _fault;
    }
}

// Meta Model API adapter, Responses protocol (10 §2, P1-02):
// dev.meta.ai/docs/protocols/responses + /docs/tool-calling.
// Stateless loop: every turn sends full state + tool definitions
// and yields one function_call or a final message. No
// previous_response_id by design: the local checkpoint is the
// memory, every request is fully inspectable in the payload log,
// and reopen works after any provider-side eviction. Disabled
// unless constructed with an explicit key + endpoint + tools;
// unit tests use a fake HttpMessageHandler only. Live round trips
// verified: 09 §14 Task 5 (2026-10-31) + P20 bounded overlap case
// (goal/evidence/p20/p20-live-receipt.json).
public sealed class MetaApiAdapter : IInvestigationModel
{
    // Highest reasoning effort the provider supports on the
    // Contributor tier. MUST NOT be "max": the provider excludes
    // max on muse-spark-1.3-contributor (10 §2). Changing this
    // string requires owner acknowledgment (09 R-g).
    public const string ReasoningEffort = "xhigh";

    public const string ModelId = "muse-spark-1.3-contributor";

    // Built-in production endpoint (dev.meta.ai/docs/authentication
    // shows the api.meta.ai base; /v1/responses is the Responses
    // path). Users never type this. The constructor still takes an
    // endpoint so tests can point at a fake handler.
    public const string DefaultEndpoint = "https://api.meta.ai/v1/responses";

    // Synthetic terminal tool (never a broker read): the model's
    // way to file a finding. Parsed into FindingDraft; the
    // coordinator validates cited evidence exactly as before.
    public const string SubmitFindingTool = "submit_finding";

    public const string SubmitFindingSchemaJson = """
        {"type":"object",
         "properties":{
           "observation":{"type":"string","description":"One observed fact from tool results, with sizes/IDs as shown."},
           "interpretation":{"type":"string","description":"What the fact may mean. No certainty beyond the evidence."},
           "evidence_ids":{"type":"array","items":{"type":"string"},"description":"file_id/dir_id/record values copied from tool results. At least one is required."},
           "limitations":{"type":"string","description":"What was not checked or could not be seen."},
           "suggested_next":{"type":"string","description":"One concrete next inspection, or empty."}},
         "required":["observation","interpretation","evidence_ids"],"additionalProperties":true}
        """;

    // Resent every turn: instructions do not persist server-side.
    // The filing rule is load-bearing: live runs show the model
    // otherwise explores, summarizes, and files nothing.
    public const string Instructions =
        "You are Sentinel's read-only storage investigator. Each turn, call exactly ONE " +
        "function, or reply with plain text (no call) to end the investigation. Use only opaque " +
        "file_id/dir_id values from tool results — never invent or write filesystem paths. Explore " +
        "unflagged areas, not just flagged ones. FILE EVERY OBSERVATION with submit_finding AS YOU " +
        "GO, citing evidence_ids you actually received: a closing summary alone records NOTHING and " +
        "unfiled observations are lost. Do not end while you hold an unfiled observation. You cannot " +
        "change anything: each filing is an advisory note the app validates. If the evidence " +
        "is exhausted or inconclusive, file what you have, then end with a short plain-text summary.";

    private readonly string _apiKey;
    private readonly string _endpoint;
    private readonly HttpClient _http;
    private readonly IReadOnlyList<IInvestigationTool> _tools;
    private readonly PayloadLog _payloads;
    private readonly InvestigationBudgets _budgets;
    private readonly bool _includeSubmitFinding;
    private readonly string _instructions;

    // U27: includeSubmitFinding=false + instructions override = the
    // Ask Q&A call shape (no tools offered at all). Defaults preserve
    // the investigation loop exactly.
    public MetaApiAdapter(
        string apiKey,
        string endpoint,
        HttpClient http,
        IReadOnlyList<IInvestigationTool> tools,
        PayloadLog payloads,
        InvestigationBudgets budgets,
        bool includeSubmitFinding = true,
        string? instructions = null)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            throw new ArgumentException("API key required.", nameof(apiKey));
        }

        foreach (var tool in tools)
        {
            try
            {
                using var schema = JsonDocument.Parse(tool.ParametersSchemaJson);
                if (!schema.RootElement.TryGetProperty("type", out _))
                {
                    throw new ArgumentException($"Tool {tool.Name} schema has no root type.");
                }
            }
            catch (JsonException ex)
            {
                throw new ArgumentException($"Tool {tool.Name} has invalid parameters schema.", ex);
            }
        }

        _apiKey = apiKey;
        _endpoint = endpoint;
        _http = http;
        _tools = tools;
        _payloads = payloads;
        _budgets = budgets;
        _includeSubmitFinding = includeSubmitFinding;
        _instructions = instructions ?? Instructions;
        // P25: this client serves one investigation session, and the
        // adapter paces every attempt against the investigation's own
        // remaining time budget (GetNextStepAsync). The default 100 s
        // client timeout would misfire on legitimate slow xhigh
        // reasoning turns AND misclassify the outcome, so it is out
        // of the picture here.
        _http.Timeout = Timeout.InfiniteTimeSpan;
    }

    public string Name => "meta-api";

    // R14.2: measured HTTP framing per message — request/status
    // line plus "Name: value" header lines as UTF-8. Counts only;
    // values are never copied anywhere.
    internal static long CountRequestOverhead(HttpRequestMessage request)
    {
        long bytes = Encoding.UTF8.GetByteCount(
            $"{request.Method} {request.RequestUri?.PathAndQuery ?? "/"} HTTP/1.1\r\n");
        bytes += CountHeaders(request.Headers);
        if (request.Content is not null)
        {
            bytes += CountHeaders(request.Content.Headers);
        }

        return bytes;
    }

    internal static long CountResponseOverhead(HttpResponseMessage response)
    {
        long bytes = Encoding.UTF8.GetByteCount(
            $"HTTP/1.1 {(int)response.StatusCode} {response.ReasonPhrase}\r\n");
        bytes += CountHeaders(response.Headers);
        if (response.Content is not null)
        {
            bytes += CountHeaders(response.Content.Headers);
        }

        return bytes;
    }

    private static long CountHeaders(System.Net.Http.Headers.HttpHeaders headers)
    {
        long bytes = 0;
        foreach (var header in headers)
        {
            bytes += Encoding.UTF8.GetByteCount(header.Key);
            foreach (string value in header.Value)
            {
                bytes += 2 + Encoding.UTF8.GetByteCount(value);
            }

            bytes += 2;
        }

        return bytes;
    }

    // A05: the inspector names the peer host, never a full URL —
    // no path, no query, nowhere for a secret to hide.
    internal static string PeerHost(string endpoint)
    {
        if (Uri.TryCreate(endpoint, UriKind.Absolute, out var uri)
            && !string.IsNullOrEmpty(uri.Host))
        {
            return uri.Host;
        }

        return "cloud model endpoint";
    }

    public async Task<ModelTurn> GetNextStepAsync(string contextJson, CancellationToken ct)
    {
        string peer = PeerHost(_endpoint);
        // P25: the in-flight attempt can never outlive the
        // investigation's own remaining time budget. This bounds
        // hung providers WITHOUT a fixed per-request guillotine: a
        // fixed 60 s timeout would abort legitimate slow xhigh
        // reasoning turns, while the duration budget is the honest
        // contract (a turn that needs longer than remains is
        // OverBudget, not Unavailable). No silent auto-retry: resume
        // continues the SAME budget, which is the bounded retry.
        TimeSpan remaining = _budgets.MaxDuration - _budgets.Elapsed;
        if (remaining <= TimeSpan.Zero)
        {
            throw new BudgetExhaustedException("Duration");
        }

        string body = BuildRequestBody(contextJson, _tools, _includeSubmitFinding, _instructions);
        // Wire accounting at the transport (P2-01): per-request
        // size guard + cumulative transmitted bytes, UTF-8.
        _budgets.CheckRequestSize(Encoding.UTF8.GetByteCount(body));
        _budgets.ChargeTransmitted(Encoding.UTF8.GetByteCount(body));
        // A05: attempted send — the destination/class/redaction the
        // inspector shows for this entry. Key material is never here.
        _payloads.Append("meta-request", body, peer, "C+F", redacted: true, truncated: false);

        using var request = new HttpRequestMessage(HttpMethod.Post, _endpoint);
        request.Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json");
        // The real key travels ONLY in the Authorization header of the
        // live call, never in any log. (Fake-handler tests assert the
        // header name; the key value is never logged.)
        request.Headers.Add("Authorization", "Bearer " + _apiKey);
        // R14.2: request-line + header framing counts as transmitted
        // (attempt cost, like the body above). Only LENGTHS are
        // summed — header values, including the key, never land in
        // any log or counter beyond their byte count. TLS record
        // bytes are outside this measurement (stated, not hidden).
        _budgets.ChargeTransmitted(CountRequestOverhead(request));

        HttpResponseMessage response;
        using var attemptCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        attemptCts.CancelAfter(remaining);
        try
        {
            response = await _http.SendAsync(request, attemptCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (
            !ct.IsCancellationRequested && attemptCts.IsCancellationRequested)
        {
            // P25: the attempt outlived the remaining time budget
            // (a hung or too-slow provider). This is budget
            // exhaustion, not a user cancel and not provider
            // unavailability: the loop ends OverBudget with partial
            // results + the continuation offer.
            _payloads.Append(
                "meta-error", "Timeout:DurationBudget",
                peer, "—", redacted: false, truncated: false);
            throw new BudgetExhaustedException("Duration");
        }
        catch (OperationCanceledException)
        {
            // A05: the attempt is distinguished from its outcome —
            // a cancelled send leaves its own marker, not silence.
            _payloads.Append(
                "meta-cancelled", "Send cancelled before a response arrived.",
                peer, "—", redacted: false, truncated: false);
            throw;
        }
        catch (Exception ex)
        {
            _payloads.Append(
                "meta-error", "Transport:" + ex.GetType().Name,
                peer, "—", redacted: false, truncated: false);
            throw new ModelUnavailableException("Transport:" + ex.GetType().Name);
        }

        string text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        _budgets.ChargeTransmitted(Encoding.UTF8.GetByteCount(text));
        _budgets.ChargeTransmitted(CountResponseOverhead(response));
        _payloads.Append("meta-response", text, peer, "model output", redacted: false, truncated: false);

        if (!response.IsSuccessStatusCode)
        {
            // A05: response received but refused — the body above plus
            // this outcome marker, never a bare throw.
            _payloads.Append(
                "meta-error", "Http" + (int)response.StatusCode,
                peer, "—", redacted: false, truncated: false);
            throw new ModelUnavailableException("Http" + (int)response.StatusCode);
        }

        if (TryReadUsage(text, out var usage))
        {
            _budgets.ChargeProviderUsage(usage);
        }

        return ParseTurn(text);
    }

    // Provider token truth (P2-01): reads the Responses usage
    // block tolerantly. Observed live 2026-10-31 (09 §14 Task 5):
    // usage carries input / output / reasoning / cached_tokens
    // style counts. Accepts long and short key spellings; nested
    // details objects as fallback. P22 recheck: dev.meta.ai/docs/
    // token-counting shows the Responses shape nests reasoning and
    // cache counts under PLURAL details objects, so those are read
    // too (singular kept for drift tolerance). Absent or malformed
    // usage = false (no invented tokens), never throws.
    public static bool TryReadUsage(string text, out ProviderUsage usage)
    {
        usage = new ProviderUsage(0, 0, 0, 0);
        try
        {
            using var doc = JsonDocument.Parse(text);
            if (doc.RootElement.ValueKind != JsonValueKind.Object
                || !doc.RootElement.TryGetProperty("usage", out var u)
                || u.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            long input = ReadCount(u, "input_tokens", "input");
            long output = ReadCount(u, "output_tokens", "output");
            long reasoning = ReadCount(u, "reasoning_tokens", "reasoning");
            long cached = ReadCount(u, "cached_tokens", "cached_input_tokens");
            if (reasoning == 0)
            {
                reasoning = ReadNested(u, "output_tokens_details", "output_token_details",
                    "reasoning_tokens", "reasoning");
            }

            if (cached == 0)
            {
                cached = ReadNested(u, "input_tokens_details", "input_token_details",
                    "cached_tokens", "cached_input_tokens");
            }

            usage = new ProviderUsage(input, output, reasoning, cached);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static long ReadNested(
        JsonElement parent, string primaryObj, string altObj,
        string primaryKey, string altKey)
    {
        if (parent.TryGetProperty(primaryObj, out var det)
            && det.ValueKind == JsonValueKind.Object)
        {
            long n = ReadCount(det, primaryKey, altKey);
            if (n > 0)
            {
                return n;
            }
        }

        if (parent.TryGetProperty(altObj, out det)
            && det.ValueKind == JsonValueKind.Object)
        {
            return ReadCount(det, primaryKey, altKey);
        }

        return 0;
    }

    private static long ReadCount(JsonElement obj, string primary, string alternate)
    {
        if (obj.TryGetProperty(primary, out var v) && v.TryGetInt64(out long n))
        {
            return Math.Max(0, n);
        }

        if (obj.TryGetProperty(alternate, out v) && v.TryGetInt64(out n))
        {
            return Math.Max(0, n);
        }

        return 0;
    }

    internal static string BuildRequestBody(
        string contextJson, IReadOnlyList<IInvestigationTool> tools,
        bool includeSubmitFinding = true, string? instructions = null)
    {
        var defs = new List<object>();
        foreach (var tool in tools)
        {
            defs.Add(new Dictionary<string, object>
            {
                ["type"] = "function",
                ["name"] = tool.Name,
                ["description"] = tool.Description,
                ["parameters"] = JsonSerializer.Deserialize<JsonElement>(
                    tool.ParametersSchemaJson),
            });
        }

        if (includeSubmitFinding)
        {
            defs.Add(new Dictionary<string, object>
            {
                ["type"] = "function",
                ["name"] = SubmitFindingTool,
                ["description"] = "REQUIRED for every observation: file one advisory finding " +
                    "from evidence already seen, before ending. Every evidence_id must be " +
                    "copied from a tool result; uncited observations are rejected and lost.",
                ["parameters"] = JsonSerializer.Deserialize<JsonElement>(
                    SubmitFindingSchemaJson),
            });
        }

        var body = new Dictionary<string, object>
        {
            ["model"] = ModelId,
            // Responses nests the control (docs/reasoning); top-level
            // reasoning_effort is Chat Completions only.
            ["reasoning"] = new Dictionary<string, object>
            {
                ["effort"] = ReasoningEffort,
            },
            ["instructions"] = instructions ?? Instructions,
            ["input"] = new object[]
            {
                new Dictionary<string, object>
                {
                    ["role"] = "user",
                    ["content"] = new object[]
                    {
                        new Dictionary<string, object>
                        {
                            ["type"] = "input_text",
                            ["text"] = contextJson,
                        },
                    },
                },
            },
        };
        if (defs.Count > 0)
        {
            // U27: Q&A calls offer no tools at all — the keys are
            // omitted, not sent empty.
            body["tool_choice"] = "auto";
            body["parallel_tool_calls"] = false;
            body["tools"] = defs;
        }

        return JsonSerializer.Serialize(body);
    }

    // Parses the Responses output[] shape ONLY (P1-02). Garbage →
    // the same "unparseable" empty turn as before (the coordinator
    // counts quiet turns and ends honestly). Provider-side failure
    // states throw ModelUnavailableException → local results stand.
    // Token truth is read separately by TryReadUsage (P2-01); the
    // raw response stays in the payload log for audit.
    public static ModelTurn ParseTurn(string text)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(text);
        }
        catch (JsonException)
        {
            return new ModelTurn(null, null, false, "unparseable");
        }

        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("output", out var output)
                || output.ValueKind != JsonValueKind.Array)
            {
                return new ModelTurn(null, null, false, "unparseable");
            }

            foreach (var item in output.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.Object
                    && item.TryGetProperty("type", out var kind)
                    && kind.GetString() == "function_call")
                {
                    return FunctionCallTurn(item);
                }
            }

            string status = root.TryGetProperty("status", out var s)
                ? s.GetString() ?? string.Empty
                : string.Empty;
            if (status is "failed" or "cancelled" or "incomplete")
            {
                throw new ModelUnavailableException("Status:" + status);
            }

            if (status is "completed" or "")
            {
                return new ModelTurn(null, null, true, ReadMessageText(output));
            }

            throw new ModelUnavailableException("Status:" + status);
        }
    }

    private static ModelTurn FunctionCallTurn(JsonElement item)
    {
        string name = item.TryGetProperty("name", out var n)
            ? n.GetString() ?? string.Empty
            : string.Empty;
        string argsJson = item.TryGetProperty("arguments", out var a)
            ? a.GetString() ?? "{}"
            : "{}";
        if (string.IsNullOrEmpty(name))
        {
            return new ModelTurn(null, null, false, "unparseable");
        }

        if (name == SubmitFindingTool)
        {
            return FindingTurn(argsJson);
        }

        // Unknown broker tools pass through: the broker rejects and
        // audits them, and the rejection re-enters history so the
        // model can self-correct. Same for malformed arguments —
        // the tool reports its missing arg.
        return new ModelTurn(
            new ToolCallRequest(name, ParseArgsObject(argsJson)),
            null, false, null);
    }

    private static ModelTurn FindingTurn(string argsJson)
    {
        string obs = string.Empty;
        string interp = string.Empty;
        string lim = string.Empty;
        string next = string.Empty;
        var ev = new List<string>();
        try
        {
            using var doc = JsonDocument.Parse(argsJson);
            var root = doc.RootElement;
            if (root.ValueKind == JsonValueKind.Object)
            {
                obs = Field(root, "observation");
                interp = Field(root, "interpretation");
                lim = Field(root, "limitations");
                next = Field(root, "suggested_next");
                if (root.TryGetProperty("evidence_ids", out var ids)
                    && ids.ValueKind == JsonValueKind.Array)
                {
                    foreach (var id in ids.EnumerateArray())
                    {
                        if (id.GetString() is string s)
                        {
                            ev.Add(s);
                        }
                    }
                }
            }
        }
        catch (JsonException)
        {
            // Empty draft: the coordinator rejects "no evidence
            // cited" and the model sees the rejection in history.
        }

        return new ModelTurn(
            null,
            new FindingDraft(obs, interp, ev, lim, next),
            false, null);
    }

    private static string Field(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var v) ? v.GetString() ?? string.Empty : string.Empty;

    // Arguments arrive as JSON values; tools read strings. Strings
    // pass through; every other JSON scalar is rendered as its
    // literal (true, 50) so "true"/"50" parse downstream exactly
    // as if typed. Objects/arrays render as compact JSON.
    private static Dictionary<string, string> ParseArgsObject(string argsJson)
    {
        var args = new Dictionary<string, string>(StringComparer.Ordinal);
        try
        {
            using var doc = JsonDocument.Parse(argsJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return args;
            }

            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                args[prop.Name] = prop.Value.ValueKind == JsonValueKind.String
                    ? prop.Value.GetString() ?? string.Empty
                    : prop.Value.GetRawText();
            }
        }
        catch (JsonException)
        {
        }

        return args;
    }

    private static string ReadMessageText(JsonElement output)
    {
        var sb = new StringBuilder();
        foreach (var item in output.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object
                || !item.TryGetProperty("type", out var kind)
                || kind.GetString() != "message"
                || !item.TryGetProperty("content", out var content)
                || content.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var part in content.EnumerateArray())
            {
                if (part.ValueKind == JsonValueKind.Object
                    && part.TryGetProperty("text", out var t)
                    && t.GetString() is string s)
                {
                    if (sb.Length > 0)
                    {
                        sb.Append('\n');
                    }

                    sb.Append(s);
                    if (sb.Length >= 2000)
                    {
                        return sb.ToString(0, 2000);
                    }
                }
            }
        }

        return sb.ToString();
    }
}
