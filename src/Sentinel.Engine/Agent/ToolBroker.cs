using System.Collections.Concurrent;
using System.Text.Json;
using Sentinel.Store;

namespace Sentinel.Engine.Agent;

public sealed class ToolRejectedException : Exception
{
    public ToolRejectedException(string reason)
        : base(reason)
    {
    }
}

public sealed record ToolResultItem(IReadOnlyDictionary<string, string> Fields);

public sealed record ToolResultGap(string Source, string Reason);

// The envelope every tool returns (10 §3). Partial results carry
// their revision and truncation openly; nothing masquerades as a
// complete snapshot.
public sealed record ToolResult(
    string ScanId,
    int EvidenceRevision,
    DateTime ObservedUtc,
    string Scope,
    ToolResultStatus Status,
    IReadOnlyList<ToolResultItem> Items,
    IReadOnlyList<ToolResultGap> Gaps,
    bool Truncated,
    string? Cursor);

public sealed class InvestigationScope
{
    public InvestigationScope(
        string investigationId,
        IReadOnlyList<string> roots,
        IReadOnlyList<string>? excluded = null)
    {
        InvestigationId = investigationId;
        Roots = roots.Select(r => ScopePaths.CanonicalRoot(r) ?? r).ToList();
        Excluded = (excluded ?? []).Select(x => ScopePaths.CanonicalRoot(x) ?? x).ToList();
    }

    public string InvestigationId { get; }

    public IReadOnlyList<string> Roots { get; }

    // A11: excluded-from-INSPECTION prefixes (enumeration prunes
    // them; the broker denies them). Deliberately separate from
    // NeverTouch, which is protection-from-ACTION only.
    public IReadOnlyList<string> Excluded { get; }

    public bool Contains(string path)
    {
        string? full = ScopePaths.CanonicalPath(path);
        if (full is null)
        {
            return false;
        }

        return Roots.Any(root => ScopePaths.IsUnder(full, root));
    }

    public bool IsExcluded(string path)
    {
        if (Excluded.Count == 0)
        {
            return false;
        }

        string? full = ScopePaths.CanonicalPath(path);
        if (full is null)
        {
            return false;
        }

        return Excluded.Any(x => ScopePaths.IsUnder(full, x));
    }
}

public interface IInvestigationTool
{
    string Name { get; }

    string Description { get; }

    // JSON Schema for the Responses tools[] array (P1-02). Must match
    // what Execute actually reads; Execute stays the validator (the
    // schema is a hint, never a security boundary).
    string ParametersSchemaJson => """{"type":"object"}""";

    // Parses + validates args, executes a bounded read, returns items.
    // May throw ToolRejectedException for forbidden/nonsense input.
    // Must never mutate inspected objects or leave the scope.
    ToolResult Execute(
        ToolBroker broker,
        InvestigationScope scope,
        IReadOnlyDictionary<string, string> args,
        CancellationToken ct);
}

// Owns the tool registry, opaque ID resolution, scope/identity
// validation, per-result size backstop, and the audit trail. The
// model NEVER supplies raw paths or SQL: it sees opaque IDs minted
// here, and every ID is re-resolved + re-scoped on use.
public sealed class ToolBroker
{
    // Backstop: tools enforce row limits; the broker refuses to emit
    // anything bigger than this regardless (10 §3).
    public const int MaxResultBytes = 256 * 1024;

    private readonly Dictionary<string, IInvestigationTool> _tools = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> _idToPath = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> _pathToId = new(StringComparer.OrdinalIgnoreCase);
    private readonly AgentStore _audit;
    private int _nextId;

    public ToolBroker(AgentStore audit)
    {
        _audit = audit;
    }

    public void Register(IInvestigationTool tool)
    {
        _tools[tool.Name] = tool;
    }

    public IReadOnlyList<IInvestigationTool> Tools => _tools.Values.ToList();

    public string MintFileId(string path)
    {
        return _pathToId.GetOrAdd(path, _ =>
        {
            var id = "f:" + Interlocked.Increment(ref _nextId);
            _idToPath[id] = path;
            return id;
        });
    }

    public string MintDirId(string path)
    {
        return _pathToId.GetOrAdd(path, _ =>
        {
            var id = "d:" + Interlocked.Increment(ref _nextId);
            _idToPath[id] = path;
            return id;
        });
    }

    public bool TryResolveId(string id, out string path)
    {
        return _idToPath.TryGetValue(id, out path!);
    }

    // P25: durable-map export, ordered by mint sequence (numeric
    // suffix, then ordinal) so persist/restore round-trips are
    // deterministic and first-mint-wins is preserved.
    public IReadOnlyList<BrokerIdEntry> ExportIds()
    {
        return _idToPath
            .Select(kv => new BrokerIdEntry(kv.Key, kv.Value))
            .OrderBy(e => MintSequence(e.Id))
            .ThenBy(e => e.Id, StringComparer.Ordinal)
            .ToList();
    }

    // P25: restores a durable map into this broker (Resume calls it
    // only after the scope gate passes). Live entries win over
    // imported ones on ID conflict; the mint counter advances past
    // every restored numeric suffix so later mints never collide.
    // Setup-time only: call before the loop runs, never mid-turn.
    public void ImportIds(IEnumerable<BrokerIdEntry> rows)
    {
        int high = 0;
        foreach (var row in rows)
        {
            if (string.IsNullOrEmpty(row.Id) || string.IsNullOrEmpty(row.Path))
            {
                continue;
            }

            _idToPath.TryAdd(row.Id, row.Path);
            _pathToId.TryAdd(row.Path, row.Id);
            int seq = MintSequence(row.Id);
            if (seq > high)
            {
                high = seq;
            }
        }

        int before;
        do
        {
            before = _nextId;
            if (high <= before)
            {
                break;
            }
        }
        while (Interlocked.CompareExchange(ref _nextId, high, before) != before);
    }

    private static int MintSequence(string id)
    {
        int colon = id.IndexOf(':');
        if (colon < 0
            || !int.TryParse(
                id.AsSpan(colon + 1), out int seq)
            || seq < 0)
        {
            return 0;
        }

        return seq;
    }

    public ToolResult Dispatch(
        InvestigationScope scope,
        ToolCallRequest request,
        InvestigationBudgets budgets,
        CancellationToken ct)
    {
        if (!_tools.TryGetValue(request.ToolName, out var tool))
        {
            _audit.RecordToolAudit(scope.InvestigationId, request.ToolName, false, "UnknownTool", 0);
            return Denied(scope, request.ToolName, "UnknownTool");
        }

        // Every dispatch of a KNOWN tool is one budgeted call — the
        // per-turn overview included. Unknown tools cost nothing.
        budgets.ChargeCall();
        ToolResult result;
        try
        {
            result = tool.Execute(this, scope, request.Args, ct);
        }
        catch (ToolRejectedException ex)
        {
            _audit.RecordToolAudit(scope.InvestigationId, request.ToolName, false, ex.Message, 0);
            return Denied(scope, request.ToolName, ex.Message);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _audit.RecordToolAudit(scope.InvestigationId, request.ToolName, false, "ToolError:" + ex.GetType().Name, 0);
            return Denied(scope, request.ToolName, "ToolError");
        }

        int bytes = Measure(result);
        if (bytes > MaxResultBytes)
        {
            _audit.RecordToolAudit(scope.InvestigationId, request.ToolName, false, "ResultTooLarge", bytes);
            return Denied(scope, request.ToolName, "ResultTooLarge: narrow the query");
        }

        budgets.ChargeEvidence(bytes);
        _audit.RecordToolAudit(scope.InvestigationId, request.ToolName, true, null, bytes);
        return result;
    }

    // Resolves an opaque ID to a live in-scope path, or throws.
    public string ResolveScopedPath(InvestigationScope scope, string id, string argName)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            throw new ToolRejectedException($"Missing {argName}.");
        }

        if (!_idToPath.TryGetValue(id, out var path))
        {
            throw new ToolRejectedException($"Unknown {argName} '{id}'.");
        }

        if (!scope.Contains(path))
        {
            throw new ToolRejectedException($"OutOfScope {argName} '{id}'.");
        }

        // A11: excluded-from-inspection is enforced at the broker,
        // not just at enumeration — a live listing must never hand
        // the model a readable handle to an excluded path.
        if (scope.IsExcluded(path))
        {
            throw new ToolRejectedException($"ExcludedScope {argName} '{id}'.");
        }

        // Links are VISIBLE in listings but never FOLLOWED: a junction
        // or symlink inside the scope can point at content outside it,
        // and the target was never audited into this investigation.
        // Every path-following tool funnels through here, so one guard
        // covers listing, stat, and excerpt alike.
        try
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                throw new ToolRejectedException($"LinkNotFollowed {argName} '{id}'.");
            }
        }
        catch (ToolRejectedException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ToolRejectedException($"PathUnreadable {argName} '{id}'.");
        }

        return path;
    }

    public static int ParseBoundedInt(
        IReadOnlyDictionary<string, string> args, string name, int fallback, int min, int max)
    {
        if (!args.TryGetValue(name, out var raw) || string.IsNullOrWhiteSpace(raw))
        {
            return fallback;
        }

        if (!int.TryParse(raw, out int value))
        {
            throw new ToolRejectedException($"Bad {name} '{raw}'.");
        }

        return Math.Clamp(value, min, max);
    }

    private static int Measure(ToolResult result)
    {
        return JsonSerializer.SerializeToUtf8Bytes(result).Length;
    }

    private static ToolResult Denied(InvestigationScope scope, string tool, string reason)
    {
        return new ToolResult(
            string.Empty, 0, DateTime.UtcNow, tool, ToolResultStatus.Denied,
            Array.Empty<ToolResultItem>(),
            [new ToolResultGap(tool, reason)], false, null);
    }
}
