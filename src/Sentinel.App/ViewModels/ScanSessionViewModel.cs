using System.IO;
using System.Net.Http;
using System.Threading;
using Sentinel.App.Services;
using Sentinel.Engine.Agent;
using Sentinel.Engine.Inventory;
using Sentinel.Engine.Scan;
using Sentinel.Store;

namespace Sentinel.App.ViewModels;

public enum ScanSessionState
{
    Idle,
    Running,
    Paused,
    Completed,
    Refused,
    Cancelled,
    Failed,
}

// Owns one scan's lifecycle: start (real orchestrated scan), pause,
// resume, cancel. Read-only in Phase 1: inventory + fingerprints.
public sealed class ScanSessionViewModel : ViewModelBase
{
    private readonly Func<SentinelDb> _dbFactory;
    private readonly Func<ScanOrchestrator> _orchestratorFactory;
    private readonly Func<AgentStore>? _agentStoreFactory;
    private readonly IUiDispatcher _dispatcher;
    private ScanSessionState _state = ScanSessionState.Idle;
    private string _modeLabel = string.Empty;
    private string _statusLine = "Pick a folder, then Scan or Turbo.";
    private string _elapsed = string.Empty;
    private string _counts = string.Empty;
    private string _investigationLine = "AI: off (no investigation this session).";
    private PauseToken? _pause;
    private CancellationTokenSource? _cts;
    private Task<OrchestratedScanResult?>? _task;
    private Task<InvestigatorOutcome?>? _investigatorTask;
    private Task? _reconcileTask;
    private readonly Func<bool>? _aiEnabledProvider;
    private readonly Func<IReadOnlyList<IInvestigationTool>, HttpClient, PayloadLog, InvestigationBudgets, ModelSource> _modelSourceFactory;
    private readonly Func<HttpClient> _httpFactory;
    private readonly Func<IReadOnlyList<string>> _excludedPrefixesProvider;
    private readonly object _liveGate = new();
    private ScanOrchestrator? _liveOrchestrator;
    private int _runSequence;
    private string? _activeInvestigationId;

    // A11: the production exclusion set, pinned by test. Own
    // data dir only — NeverTouch is protection-from-action and
    // must never appear here (separation is the point).
    public static IReadOnlyList<string> DefaultExclusions() => [SentinelPaths.DataDirectory];

    // Last investigation's payloads for the Settings inspector.
    public IReadOnlyList<PayloadEntry> LastPayloads { get; private set; } = [];

    // A05: the same capture with capacity accounting (evicted /
    // total), so the inspector can state what fell off the ring.
    public PayloadHistorySnapshot? LastPayloadHistory { get; private set; }

    public ScanSessionViewModel(
        Func<SentinelDb> dbFactory,
        Func<ScanOrchestrator>? orchestratorFactory = null,
        IUiDispatcher? dispatcher = null,
        Func<AgentStore>? agentStoreFactory = null,
        Func<bool>? aiEnabledProvider = null,
        Func<IReadOnlyList<IInvestigationTool>, HttpClient, PayloadLog, InvestigationBudgets, ModelSource>? modelSourceFactory = null,
        Func<HttpClient>? httpFactory = null,
        Func<IReadOnlyList<string>>? excludedPrefixesProvider = null)
    {
        _dbFactory = dbFactory;
        // A11: Sentinel never scans its own data dir (live DBs
        // would churn fingerprints mid-scan). The provider seam
        // lets tests substitute fixture prefixes.
        _excludedPrefixesProvider = excludedPrefixesProvider
            ?? DefaultExclusions;
        _orchestratorFactory = orchestratorFactory ?? (() => new ScanOrchestrator(dbFactory()));
        _agentStoreFactory = agentStoreFactory;
        _dispatcher = dispatcher ?? new ImmediateDispatcher();
        _aiEnabledProvider = aiEnabledProvider;
        // Default: no endpoint source, so offline unless a key AND an
        // endpoint exist — MainViewModel passes the real closure.
        _modelSourceFactory = modelSourceFactory
            ?? ((tools, http, payloads, budgets) => InvestigationModelFactory.Create(
                new CloudKeyStore().ReadKey(), tools, http, payloads, budgets));
        _httpFactory = httpFactory ?? (() => new HttpClient());
    }

    public ScanSessionState State
    {
        get => _state;
        private set
        {
            if (Set(ref _state, value))
            {
                Raise(nameof(CanStart));
                Raise(nameof(CanPause));
                Raise(nameof(CanResume));
                Raise(nameof(CanCancel));
            }
        }
    }

    public bool CanStart => State is ScanSessionState.Idle or ScanSessionState.Completed or ScanSessionState.Refused or ScanSessionState.Cancelled or ScanSessionState.Failed;

    public bool CanPause => State == ScanSessionState.Running;

    public bool CanResume => State == ScanSessionState.Paused;

    // A live investigator outlives fast collections: cancel stays
    // available until it lands too, or the user cannot stop a
    // 10-minute cloud loop from a "Completed" scan.
    public bool CanCancel => State is ScanSessionState.Running or ScanSessionState.Paused
        || (_investigatorTask is { IsCompleted: false });

    public string ModeLabel
    {
        get => _modeLabel;
        private set => Set(ref _modeLabel, value);
    }

    public string StatusLine
    {
        get => _statusLine;
        private set => Set(ref _statusLine, value);
    }

    public string Elapsed
    {
        get => _elapsed;
        private set => Set(ref _elapsed, value);
    }

    public string Counts
    {
        get => _counts;
        private set => Set(ref _counts, value);
    }

    public IReadOnlyList<InventoryGap> Gaps { get; private set; } = [];

    // Last finished scan (any outcome with a result row): feeds the
    // Ask panel's grounded scan answers. Null until the first run.
    public OrchestratedScanResult? LastResult { get; private set; }

    public string LastRoot { get; private set; } = string.Empty;

    // Investigation Strip (02 §5.9): AI status is SEPARATE from
    // collection status. Until a cloud key is configured the
    // investigator runs offline and says so honestly.
    public string InvestigationLine
    {
        get => _investigationLine;
        private set => Set(ref _investigationLine, value);
    }

    public IReadOnlyList<string> ProvisionalFindings { get; private set; } = [];

    // P21: the priority lane into the RUNNING scan, for watcher
    // discoveries. False when no scan is draining (the watcher
    // falls back to its bounded delta). Never throws.
    public bool TryEnqueuePriority(string path)
    {
        ScanOrchestrator? orch;
        lock (_liveGate)
        {
            orch = _liveOrchestrator;
        }

        try
        {
            return orch?.TryEnqueuePriorityLive(path) ?? false;
        }
        catch
        {
            return false;
        }
    }

    private void SetLiveOrchestrator(ScanOrchestrator? orchestrator)
    {
        lock (_liveGate)
        {
            _liveOrchestrator = orchestrator;
        }
    }

    public void Start(ScanMode mode, string root, int? balancedCapPercent = null)
    {
        if (!CanStart)
        {
            return;
        }

        int cap = balancedCapPercent ?? 25;

        // Stop any orphaned investigator from a previous scan (it may
        // outlive its collection) and invalidate its pending posts.
        // Never disposed: tasks still holding the token would throw.
        _cts?.Cancel();
        Interlocked.Increment(ref _runSequence);
        _pause = new PauseToken();
        _cts = new CancellationTokenSource();
        LastRoot = root;
        Raise(nameof(LastRoot));
        var pause = _pause;
        var ct = _cts.Token;
        int labelCap = mode == ScanMode.Balanced
            ? Math.Clamp(balancedCapPercent ?? 25, 10, 30)
            : 0;
        ModeLabel = mode switch
        {
            ScanMode.Eco => "ECO · ≤15% · idle-only",
            ScanMode.Balanced => $"BALANCED · ≤{labelCap}%",
            ScanMode.Turbo => "TURBO · ≤60%",
            _ => mode.ToString(),
        };
        State = ScanSessionState.Running;
        StatusLine = $"Scanning {root}…";
        Elapsed = string.Empty;
        Counts = string.Empty;
        Gaps = [];
        InvestigationLine = "AI: investigating…";
        ProvisionalFindings = [];
        Raise(nameof(ProvisionalFindings));
        var started = DateTime.UtcNow;
        var preview = new EvidencePreviewHub();
        // A11: one exclusion set for collection AND investigation —
        // the AI scope always equals the scan scope.
        IReadOnlyList<string> excluded;
        try
        {
            excluded = _excludedPrefixesProvider() ?? [];
        }
        catch
        {
            excluded = [];
        }

        // The investigator runs CONCURRENTLY with collection over hub
        // previews (10 §4). Model comes from the factory: live cloud
        // iff endpoint + Credential Manager key exist, else honest
        // offline. Owns nothing UI-threaded; all posts are guarded
        // by the run sequence so a stale investigator cannot paint
        // over a newer scan.
        int myRun = _runSequence;
        _investigatorTask = Task.Run(async () =>
        {
            AgentStore? ownedStore = null;
            try
            {
                if (_aiEnabledProvider?.Invoke() == false)
                {
                    PostIfCurrent(myRun, () =>
                        InvestigationLine = "AI: off (disabled in Settings).");
                    return null;
                }

                var agentStore = _agentStoreFactory?.Invoke();
                if (agentStore is null)
                {
                    PostIfCurrent(myRun, () =>
                        InvestigationLine = "AI: off (no investigation store).");
                    return null;
                }

                ownedStore = agentStore;

                var broker = new ToolBroker(agentStore);
                using var db = _dbFactory();
                using var http = _httpFactory();
                var toolList = new List<IInvestigationTool>(
                    new StorageTools(preview, db).All)
                {
                    new ExcerptTools(preview),
                    new EventTools(preview),
                };
                foreach (var tool in toolList)
                {
                    broker.Register(tool);
                }

                var payloads = new PayloadLog();
                // ONE budgets instance shared by adapter (wire + usage
                // charging at the transport) and coordinator (evidence
                // charging + checkpoints). Created before the factory
                // so the live adapter can charge into it (P2-01).
                var budgets = new InvestigationBudgets();
                var source = _modelSourceFactory(toolList, http, payloads, budgets);
                // A11: resume only when the stored scope fingerprint
                // matches today's scope — a changed root or exclusion
                // set starts fresh instead of continuing blind.
                string fingerprint = ScopeFingerprint.Compute([root], excluded);
                string? resumeId = FindResumable(agentStore, root, _activeInvestigationId, fingerprint);
                InvestigationCoordinator coordinator;
                string investigationId;
                bool resumed = resumeId is not null;
                if (resumed)
                {
                    investigationId = resumeId!;
                    coordinator = InvestigationCoordinator.Resume(
                        agentStore, investigationId, [root],
                        preview, broker, source.Model,
                        budgets, payloads, excluded);
                }
                else
                {
                    investigationId = Guid.NewGuid().ToString("N");
                    coordinator = new InvestigationCoordinator(
                        investigationId, [root],
                        "Investigate this storage scan.",
                        preview, broker, source.Model,
                        agentStore, budgets, payloads, excluded);
                }

                _activeInvestigationId = investigationId;
                PostIfCurrent(myRun, () => InvestigationLine =
                    resumed
                        ? $"AI: resumed investigation {investigationId[..8]} ({source.Description})…"
                        : source.IsLive
                            ? "AI: investigating (cloud)…"
                            : $"AI: {source.Description}…");
                coordinator.ProvisionalFinding += _ =>
                {
                    var snapshot = coordinator.Findings.Select(FormatFinding).ToList();
                    PostIfCurrent(myRun, () =>
                    {
                        ProvisionalFindings = snapshot;
                        Raise(nameof(ProvisionalFindings));
                    });
                };
                var status = await coordinator.RunAsync(ct).ConfigureAwait(false);
                var captured = payloads.Entries;
                var history = payloads.Snapshot();
                var finals = coordinator.Findings.Select(FormatFinding).ToList();
                PostIfCurrent(myRun, () =>
                {
                    InvestigationLine = LineFor(status, source, coordinator);
                    ProvisionalFindings = finals;
                    Raise(nameof(ProvisionalFindings));
                    LastPayloads = captured;
                    LastPayloadHistory = history;
                    Raise(nameof(LastPayloads));
                    Raise(nameof(CanCancel));
                });
                if (_activeInvestigationId == investigationId)
                {
                    _activeInvestigationId = null;
                }

                // agentStore ownership passes to the reconcile step
                // (reconciliation checkpoints through it). It is
                // disposed there, exactly once, come what may.
                ownedStore = null;
                return new InvestigatorOutcome(coordinator, agentStore);
            }
            catch (OperationCanceledException)
            {
                ownedStore?.Dispose();
                PostIfCurrent(myRun, () =>
                {
                    InvestigationLine = "AI: cancelled.";
                    Raise(nameof(CanCancel));
                });
                return null;
            }
            catch (Exception)
            {
                ownedStore?.Dispose();
                PostIfCurrent(myRun, () =>
                {
                    InvestigationLine = "AI: unavailable (investigation error).";
                    Raise(nameof(CanCancel));
                });
                return null;
            }
        });

        _task = Task.Run(async () =>
        {
            OrchestratedScanResult? result = null;
            var orchestrator = _orchestratorFactory();
            SetLiveOrchestrator(orchestrator);
            try
            {
                result = await orchestrator.RunAsync(
                    new ScanOptions(mode, [root], balancedCapPercent: cap, excludedPathPrefixes: excluded),
                    pause, ct, preview).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                result = null;
            }
            catch (Exception ex)
            {
                // A09: collection posts are run-guarded like the
                // investigator's — a superseded scan (cancelled
                // then replaced) can never paint over its
                // successor. Unreachable via CanStart today, but
                // the invariant no longer depends on the gate.
                int failedRun = myRun;
                _dispatcher.Post(() =>
                {
                    if (!IsCurrent(failedRun))
                    {
                        return;
                    }

                    StatusLine = "Scan failed: " + ex.GetType().Name;
                    State = ScanSessionState.Failed;
                });
                return null;
            }
            finally
            {
                SetLiveOrchestrator(null);
            }

            var elapsed = DateTime.UtcNow - started;
            int completedRun = myRun;
            _dispatcher.Post(() =>
            {
                if (!IsCurrent(completedRun))
                {
                    return;
                }

                Elapsed = $"in {elapsed.TotalSeconds:F1}s";
                if (result is null)
                {
                    StatusLine = "Scan cancelled.";
                    State = ScanSessionState.Cancelled;
                    return;
                }

                Counts = $"{CountText.Of(result.FilesSeen, "file")} · {FormatBytes(result.BytesSeen)} · {CountText.Of(result.FilesHashed, "file")} hashed · {CountText.Of(result.Gaps.Count, "gap")}";
                Gaps = result.Gaps;
                Raise(nameof(Gaps));
                LastResult = result;
                Raise(nameof(LastResult));
                if (result.Outcome == ScanOutcome.Completed)
                {
                    StatusLine = $"Done. Generation {result.Generation}.";
                    State = ScanSessionState.Completed;
                }
                else if (result.Outcome == ScanOutcome.Cancelled)
                {
                    StatusLine = "Scan cancelled.";
                    State = ScanSessionState.Cancelled;
                }
                else if (result.Outcome == ScanOutcome.Failed)
                {
                    StatusLine = "Scan failed: " + (result.Error ?? "unknown error")
                        + ". No partial results were kept.";
                    State = ScanSessionState.Failed;
                }
                else
                {
                    StatusLine = result.RefusalReason ?? "Scan refused.";
                    State = ScanSessionState.Refused;
                }
            });
            return result;
        });

        // Reconciliation runs when BOTH arms land: findings confirmed
        // or marked stale against the committed generation. Never
        // blocks collection's own completion line.
        _reconcileTask = ReconcileWhenReadyAsync(myRun, _task, _investigatorTask);
    }

    public void Pause()
    {
        if (State != ScanSessionState.Running || _pause is null)
        {
            return;
        }

        _pause.Pause();
        State = ScanSessionState.Paused;
        StatusLine = "Paused.";
    }

    public void Resume()
    {
        if (State != ScanSessionState.Paused || _pause is null)
        {
            return;
        }

        _pause.Resume();
        State = ScanSessionState.Running;
        StatusLine = "Resumed.";
    }

    public void Cancel()
    {
        if (!CanCancel)
        {
            return;
        }

        _pause?.Resume(); // A paused worker must wake to observe cancellation.
        _cts?.Cancel();
    }

    public Task<OrchestratedScanResult?>? RunningTask => _task;

    public Task? InvestigatorTask => _investigatorTask;

    public Task? ReconcileTask => _reconcileTask;

    private async Task ReconcileWhenReadyAsync(
        int myRun,
        Task<OrchestratedScanResult?> collection,
        Task<InvestigatorOutcome?>? investigator)
    {
        InvestigatorOutcome? inv = null;
        OrchestratedScanResult? result = null;
        try
        {
            if (investigator is not null)
            {
                await Task.WhenAll(collection, investigator).ConfigureAwait(false);
                inv = investigator.Result;
            }
            else
            {
                await collection.ConfigureAwait(false);
            }

            result = collection.Result;
        }
        catch
        {
            return; // Both arms are no-throw by construction; defensive.
        }

        try
        {
            if (!IsCurrent(myRun)
                || result?.Outcome != ScanOutcome.Completed
                || inv?.Coordinator is not { } coordinator
                || coordinator.Findings.Count == 0)
            {
                return;
            }

            using var db = _dbFactory();
            await coordinator.ReconcileAsync(db, result.Generation).ConfigureAwait(false);
            var finals = coordinator.Findings.Select(FormatFinding).ToList();
            string detail = coordinator.StatusDetail ?? "reconciled";
            PostIfCurrent(myRun, () =>
            {
                ProvisionalFindings = finals;
                Raise(nameof(ProvisionalFindings));
                InvestigationLine = $"AI: {detail}.";
            });
        }
        finally
        {
            inv?.OwnedStore?.Dispose();
        }
    }

    private void PostIfCurrent(int run, Action update)
    {
        _dispatcher.Post(() =>
        {
            if (IsCurrent(run))
            {
                update();
            }
        });
    }

    private bool IsCurrent(int run) => Volatile.Read(ref _runSequence) == run;

    // Crash/close-mid-run recovery: the newest still-"Investigating"
    // checkpoint for this exact scope resumes cold. Cancelled and
    // finished investigations never auto-resume; neither does the
    // run still active in this session — nor any checkpoint whose
    // scope fingerprint (roots + exclusions + excerpt policy) no
    // longer matches (A11).
    private static string? FindResumable(
        AgentStore store, string root, string? excludeId, string currentFingerprint)
    {
        string want;
        try
        {
            want = Path.GetFullPath(root);
        }
        catch
        {
            return null;
        }

        foreach (var inv in store.ListInvestigations(50))
        {
            if (inv.Id == excludeId
                || !ResumeGate.IsResumable(inv.Status, inv.ScopeFingerprint, currentFingerprint))
            {
                continue;
            }

            string label;
            try
            {
                label = Path.GetFullPath(inv.ScanLabel);
            }
            catch
            {
                continue;
            }

            if (label.Equals(want, StringComparison.OrdinalIgnoreCase))
            {
                return inv.Id;
            }
        }

        return null;
    }

    private static string FormatFinding(AgentFinding f) =>
        $"{f.Status.ToString().ToLowerInvariant()}: {f.Observation} ({f.Evidence.Count} evidence)";

    private static string LineFor(
        InvestigationStatus status, ModelSource source, InvestigationCoordinator coordinator)
    {
        int n = coordinator.Findings.Count;
        return status switch
        {
            InvestigationStatus.Done => n == 0
                ? "AI: done — no findings."
                : $"AI: done — {CountText.Of(n, "finding")}.",
            InvestigationStatus.Unavailable =>
                $"AI: unavailable ({FriendlyReason(coordinator.StatusDetail)}) — local results stand.",
            InvestigationStatus.Cancelled => "AI: cancelled.",
            InvestigationStatus.OverBudget => $"AI: paused over budget — {n} provisional kept.",
            InvestigationStatus.Failed => "AI: investigation error.",
            _ => $"AI: {status}.",
        };
    }

    private static string FriendlyReason(string? detail) => detail switch
    {
        "NoKey" => "no cloud key",
        null or "" => "unknown reason",
        var d when d.Length > 80 => d[..80],
        var d => d,
    };

    private sealed record InvestigatorOutcome(
        InvestigationCoordinator Coordinator,
        AgentStore OwnedStore);

    private static string FormatBytes(long bytes)
    {
        const long GB = 1024L * 1024L * 1024L;
        const long MB = 1024L * 1024L;
        if (bytes >= GB)
        {
            return $"{bytes / (double)GB:F1} GB";
        }

        if (bytes >= MB)
        {
            return $"{bytes / (double)MB:F1} MB";
        }

        return $"{bytes / 1024.0:F0} KB";
    }
}
