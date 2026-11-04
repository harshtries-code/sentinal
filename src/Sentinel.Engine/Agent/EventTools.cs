using Sentinel.Engine.SystemInventory;

namespace Sentinel.Engine.Agent;

public sealed class EventTools : IInvestigationTool
{
    public const int MaxRows = 200;

    private static readonly HashSet<string> AllowedChannels = new(StringComparer.OrdinalIgnoreCase)
    {
        "System",
        "Application",
    };

    private readonly EvidencePreviewHub _hub;

    public EventTools(EvidencePreviewHub hub)
    {
        _hub = hub;
    }

    public string Name => "query_events";

    public string Description =>
        "Targeted Windows event reads. Args: channel (System|Application, " +
        "required), provider?, max_level 1-4 (default 3), since_hours " +
        "1-720 (default 168), limit 1-200. Bounded rows with record IDs.";

    public string ParametersSchemaJson => """
        {"type":"object",
         "properties":{
           "channel":{"type":"string","enum":["System","Application"]},
           "provider":{"type":"string","maxLength":128,"description":"Event provider name filter. No wildcards."},
           "max_level":{"type":"integer","minimum":1,"maximum":4,"default":3,"description":"1 critical .. 4 informational."},
           "since_hours":{"type":"integer","minimum":1,"maximum":720,"default":168},
           "limit":{"type":"integer","minimum":1,"maximum":200,"default":50}},
         "required":["channel"],"additionalProperties":true}
        """;

    public ToolResult Execute(
        ToolBroker broker, InvestigationScope scope,
        IReadOnlyDictionary<string, string> args, CancellationToken ct)
    {
        if (!args.TryGetValue("channel", out var channel) || !AllowedChannels.Contains(channel))
        {
            throw new ToolRejectedException("Bad channel (System|Application only).");
        }

        args.TryGetValue("provider", out var provider);
        if (provider is not null && (provider.Length > 128 || provider.Contains('*')))
        {
            throw new ToolRejectedException("Bad provider.");
        }

        int maxLevel = ToolBroker.ParseBoundedInt(args, "max_level", 3, 1, 4);
        int sinceHours = ToolBroker.ParseBoundedInt(args, "since_hours", 168, 1, 720);
        int limit = ToolBroker.ParseBoundedInt(args, "limit", 50, 1, MaxRows);

        var collected = EventCollector.CollectTargeted(
            channel, provider, maxLevel,
            DateTime.UtcNow.AddHours(-sinceHours), limit);

        var items = collected.Records.Select(r => new ToolResultItem(
            new Dictionary<string, string>
            {
                ["record_id"] = r.RecordId.ToString(),
                ["event_id"] = r.Id.ToString(),
                ["level"] = r.Level,
                ["time_utc"] = r.TimeUtc.ToString("O"),
                ["provider"] = r.Provider,
                ["message"] = SecretRedactor.RedactUserPrefix(
                    SecretRedactor.RedactSecrets(r.Message)),
            })).ToList();

        var snap = _hub.Snapshot();
        var gaps = collected.Gaps.Select(g =>
            new ToolResultGap(g.Source, g.Reason)).ToList();
        return new ToolResult(
            snap.ScanId, snap.Revision, DateTime.UtcNow, Name,
            collected.Status == CollectionStatus.Failed
                ? ToolResultStatus.Error : ToolResultStatus.Ok,
            items, gaps, collected.Truncated, null);
    }
}
