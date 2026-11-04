using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Sentinel.App.Services;
using Sentinel.Engine.Actions;
using Sentinel.Engine.Agent;
using Sentinel.Engine.Ask;
using Sentinel.Engine.CrashDoctor;
using Sentinel.Engine.Drivers;
using Sentinel.Engine.Policy;
using Sentinel.Engine.Scan;
using Sentinel.Engine.SystemInventory;
using Sentinel.Engine.Watch;
using Sentinel.Store;

namespace Sentinel.App.ViewModels;

// Root view-model: owns the session, pages, status bar, and panel.
public sealed class MainViewModel : ViewModelBase
{
    private string _scanRoot;
    private string? _dbError;
    private string? _lastRecoveryNote;
    private readonly string _databasePath;
    private readonly Func<SentinelDb> _dbFactory;
    private readonly IUiDispatcher _dispatcher;
    private readonly Func<ProcessWatcher> _watcherFactory;
    private ProcessWatcher? _watcher;
    private int _deltaRunning;
    private string _lastDeltaNote = string.Empty;

    // E33: one process-wide dispatcher (idempotency keys + refusal
    // audit live here). The audit log opens lazily — constructing
    // the shell must never touch the audit store.
    private readonly ActionDispatcher _actionDispatcher;
    private ActionAuditLog? _auditLog;
    private VaultStore? _vaultStore;
    private DriverBlocklist? _driverBlocklist;

    public MainViewModel(
        Func<SentinelDb> dbFactory,
        IUiDispatcher dispatcher,
        string? databasePathOverride = null,
        Func<ProcessWatcher>? watcherFactory = null,
        string? settingsPathOverride = null,
        IConfirmSheetHost? sheetHost = null,
        Action? viewHistory = null,
        IDriverSheetHost? driverSheetHost = null,
        IDefenderScanSheetHost? defenderScanSheetHost = null,
        IQuarantineSheetHost? quarantineSheetHost = null)
    {
        _databasePath = databasePathOverride ?? SentinelPaths.DatabasePath;
        _dbFactory = dbFactory;
        _dispatcher = dispatcher;
        // P21: the factory seam lets tests inject a scripted-source
        // watcher; production gets live sources + A11 exclusions.
        _watcherFactory = watcherFactory ?? (() => new ProcessWatcher(
            new LiveProcessSnapshotSource(),
            new FolderEventSource(
                WatchOptions.DefaultFolders(),
                WatchOptions.Default().ExeExtensions),
            WatchOptions.Default(),
            ScanSessionViewModel.DefaultExclusions));
        Settings = new SettingsViewModel(
            new SettingsStore(settingsPathOverride ?? SentinelPaths.SettingsPath),
            dbFactory,
            () => new AgentStore(SentinelPaths.AgentDatabasePath));
        Session = new ScanSessionViewModel(
            dbFactory,
            () => new Sentinel.Engine.Scan.ScanOrchestrator(
                dbFactory(), pauseOnLowBattery: Settings.PauseOnLowBattery,
                neverTouch: Settings.NeverTouch),
            dispatcher,
            () => new AgentStore(SentinelPaths.AgentDatabasePath),
            () => Settings.AiEnabled,
            (tools, http, payloads, budgets) => InvestigationModelFactory.Create(
                new CloudKeyStore().ReadKey(), tools, http, payloads, budgets));
        Settings.PayloadProvider = () => Session.LastPayloads
            .Select(p => $"[{p.Kind} {p.AtUtc:u}] {p.Text}")
            .ToList();
        Settings.PayloadHistoryProvider = () => Session.LastPayloadHistory;
        Overview = new OverviewViewModel(
            dbFactory,
            () => new AgentStore(SentinelPaths.AgentDatabasePath),
            () => Settings.NeverTouch);
        // P27: the Performance page persists drive history + reads
        // crash trends from the Passport, and formats the last
        // scan's cost from the live session.
        Performance = new PerformanceViewModel(
            () => new PassportDb(SentinelPaths.PassportDatabasePath),
            () => PerformanceViewModel.FormatScanCost(Session.LastResult, Session.LastRoot));
        // E33/E35: the action choke point. clean_items_to_vault is
        // the ONLY registered executor — the first lawful reversible
        // action. Registration failure fails the shell fast: starting
        // without the executor while offering its button would lie.
        var auditSink = new AuditLogSink(() => _auditLog ??= OpenAuditLog());
        _actionDispatcher = new ActionDispatcher(
            auditSink,
            new SettingsPermissionLevels(() => Settings.Current));
        if (!_actionDispatcher.RegisterExecutor("clean_items_to_vault", new CleanExecutor(
                () => _vaultStore ??= OpenVault(),
                new DiskVaultFileIO(),
                SentinelPaths.VaultDirectory,
                () => new RiskClassifier(Settings.NeverTouch.ToArray()),
                new StaticEvidenceSignerReader(),
                auditSink,
                dbFactory)))
        {
            throw new InvalidOperationException(
                "clean_items_to_vault is not Active — refusing to start without the lawful executor.");
        }

        // D43: the driver pair (D42 executors, live VM-battery ops in
        // production). Registration failure fails the shell fast, for
        // the same reason as clean: no dead driver buttons.
        Func<DriverBlocklist> driverBlocklist =
            () => _driverBlocklist ??= new DriverBlocklist(
                () => new PassportDb(SentinelPaths.PassportDatabasePath));
        var driverOps = new WindowsDriverOps();
        var srClient = new SrClient();
        if (!_actionDispatcher.RegisterExecutor("driver_update_from_ladder",
                new DriverUpdateExecutor(driverOps, srClient, driverBlocklist, auditSink)))
        {
            throw new InvalidOperationException(
                "driver_update_from_ladder is not Active — refusing to start without the lawful executor.");
        }

        if (!_actionDispatcher.RegisterExecutor("driver_rollback",
                new DriverRollbackExecutor(driverOps, srClient, driverBlocklist, auditSink)))
        {
            throw new InvalidOperationException(
                "driver_rollback is not Active — refusing to start without the lawful executor.");
        }

        // T50: Defender scan (dangerous-list: live scans run in the
        // VM battery; EICAR/benign plumbing never on the host).
        if (!_actionDispatcher.RegisterExecutor("defender_scan",
                new DefenderScanExecutor(
                    new ProcessDefenderProcess(),
                    () => DefenderCollector.CollectDetections(25).Records,
                    auditSink)))
        {
            throw new InvalidOperationException(
                "defender_scan is not Active — refusing to start without the lawful executor.");
        }

        // T52: quarantine restore (dangerous-list: the live restore
        // round-trip runs in the VM battery; never on the host).
        if (!_actionDispatcher.RegisterExecutor("quarantine_restore",
                new QuarantineRestoreExecutor(
                    new ProcessDefenderProcess(),
                    () => QuarantineCollector.Collect().Records,
                    auditSink)))
        {
            throw new InvalidOperationException(
                "quarantine_restore is not Active — refusing to start without the lawful executor.");
        }

        var vaultUndo = new VaultUndoService(
            () => _vaultStore ??= OpenVault(),
            new DiskVaultFileIO(),
            SentinelPaths.VaultDirectory,
            auditSink);
        CleanerActionServices? cleanerActions = sheetHost is null ? null : new CleanerActionServices(
            () => _actionDispatcher,
            vaultUndo,
            sheetHost,
            ScanSessionViewModel.DefaultExclusions(),
            viewHistory);
        Cleaner = new CleanerViewModel(dbFactory, () => Settings.NeverTouch, cleanerActions);
        DriverActionServices? driverActions = driverSheetHost is null ? null
            : new DriverActionServices(
                () => _actionDispatcher,
                driverSheetHost,
                () => driverOps,
                srClient,
                driverBlocklist,
                viewHistory);
        Drivers = new DriversViewModel(
            () => new PassportDb(SentinelPaths.PassportDatabasePath),
            driverActions);
        ThreatActionServices? threatActions = defenderScanSheetHost is null ? null
            : new ThreatActionServices(
                () => _actionDispatcher,
                defenderScanSheetHost,
                viewHistory,
                quarantineSheetHost);
        Threats = new ThreatsViewModel(threatActions);
        Crashes = new CrashesViewModel(() => new PassportDb(SentinelPaths.PassportDatabasePath));
        History = new HistoryViewModel(
            dbFactory,
            () => new AgentStore(SentinelPaths.AgentDatabasePath),
            new HistoryActionServices(
                () => _auditLog ??= OpenAuditLog(),
                () => _vaultStore ??= OpenVault(),
                vaultUndo,
                () => Settings.Current.VaultReviewDays,
                SentinelPaths.VaultDirectory));
        // T55: reports read the same audit log the History page
        // shows (recent-actions section + coverage).
        Reports = new ReportsViewModel(dbFactory, () => _auditLog ??= OpenAuditLog());
        Ask = new AskPanelViewModel(
            BuildAskContext, dispatcher, () => Settings.AiEnabled,
            new AskCloudExplainer(
                () => new CloudKeyStore().ReadKey(), () => new HttpClient(), AskPayloads));
        Status = new StatusBarViewModel();
        Status.WatchLineProvider = WatchLineForStatus;
        // P21: the toggle starts/stops the live watch; the watcher
        // itself starts via StartWatching (called by the window, so
        // tests can construct this model without spawning threads).
        Settings.WatchToggled += (_, _) => ApplyWatchSetting();
        RebuildDataCommand = new RelayCommand(_ => RebuildData());
        IsElevated = new WindowsPrincipal(WindowsIdentity.GetCurrent())
            .IsInRole(WindowsBuiltInRole.Administrator);
        // First-run scope is the whole system drive (board 12: "All
        // local volumes"): a Documents-only default made Storage
        // report a near-empty PC. Users can scope down via Browse.
        _scanRoot = SystemScanRoot;

        // A08: read-only startup probe — a read-write open would
        // delete a corrupt store's -wal sidecar before the user
        // ever clicks Rebuild.
        string? health = SentinelDb.ProbeHealth(_databasePath);
        if (health is not null)
        {
            DbError = "Local data looks corrupt (" + health + ") — rebuild it below. Scans will re-discover everything.";
        }

        RefreshBanners();
    }

    public IReadOnlyList<string> PageNames { get; } =
    [
        "Overview", "Performance", "Storage", "Drivers", "Threats",
        "Crashes", "History", "Reports", "Settings",
    ];

    public ScanSessionViewModel Session { get; }

    public OverviewViewModel Overview { get; }

    public PerformanceViewModel Performance { get; }

    public CleanerViewModel Cleaner { get; }

    // The process-wide action choke point (E30). Pages offer domain
    // flows; every mutation still funnels through here.
    public ActionDispatcher Actions => _actionDispatcher;

    private ActionAuditLog OpenAuditLog() => new(
        SentinelPaths.AuditDatabasePath,
        typeof(MainViewModel).Assembly.GetName().Version?.ToString() ?? "dev",
        MetaApiAdapter.ModelId,
        KnowledgePack.PackVersion);

    private static VaultStore OpenVault() => new(SentinelPaths.VaultDatabasePath);

    public DriversViewModel Drivers { get; }

    public ThreatsViewModel Threats { get; }

    public CrashesViewModel Crashes { get; }

    public HistoryViewModel History { get; }

    public ReportsViewModel Reports { get; }

    public SettingsViewModel Settings { get; }

    public AskPanelViewModel Ask { get; }

    // U27: Ask cloud calls append here (never to the scan's payload
    // log — they are not scan payloads). Inspector merge is U26's call.
    public PayloadLog AskPayloads { get; } = new();

    public bool IsElevated { get; }

    private bool _isOffline;

    public bool IsOffline
    {
        get => _isOffline;
        private set => Set(ref _isOffline, value);
    }

    // Nav collapse (02 §2): labels hide below 1100px window width;
    // badges + tooltips + automation names carry the meaning.
    private bool _isNavCollapsed;

    public bool IsNavCollapsed
    {
        get => _isNavCollapsed;
        set => Set(ref _isNavCollapsed, value);
    }

    public string OfflineBanner =>
        "You are offline — scans, tiers, crashes, and history all work. Cloud answers are unavailable.";

    public string AdminBanner =>
        "Running without admin rights — some driver and event reads may report gaps instead of rows.";

    // U20 (02 §2 topbar): page context carries the PC name.
    public string PcName => Environment.MachineName;

    public string? DbError
    {
        get => _dbError;
        private set => Set(ref _dbError, value);
    }

    // A08: what the last rebuild did ("history kept" /
    // "quarantine/..." / null when none ran or it failed).
    public string? LastRecoveryNote
    {
        get => _lastRecoveryNote;
        private set => Set(ref _lastRecoveryNote, value);
    }

    public RelayCommand RebuildDataCommand { get; }

    public void RefreshBanners()
    {
        try
        {
            IsOffline = !NetworkInterface.GetIsNetworkAvailable();
        }
        catch
        {
            IsOffline = false;
        }
    }

    // A08: rebuild the fingerprint cache while preserving run
    // history. Corrupt stores are quarantined, never deleted;
    // the agent store is untouched (explicit wipe is N63). A
    // failed rebuild keeps its error instead of clearing it.
    private void RebuildData()
    {
        var outcome = StoreRecovery.TryRebuildFingerprintCache(_databasePath);
        if (outcome.Success)
        {
            DbError = null;
            LastRecoveryNote = outcome.Detail;
        }
        else
        {
            DbError = "Rebuild " + outcome.Detail;
            LastRecoveryNote = null;
        }
    }

    public StatusBarViewModel Status { get; }

    public string ScanRoot
    {
        get => _scanRoot;
        set
        {
            if (Set(ref _scanRoot, value))
            {
                Raise(nameof(ScanActionLabel));
            }
        }
    }

    public static string SystemScanRoot => Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";

    public string ScanActionLabel => string.Equals(
        ScanRoot.Trim().TrimEnd('\\', '/'), SystemScanRoot.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase)
        ? "Scan this PC"
        : "Scan folder";

    // P21: priority-watch lifecycle. The window calls StartWatching
    // once; the settings toggle calls ApplyWatchSetting; OnClosed
    // calls Shutdown. Tests inject a scripted watcher factory and
    // drive these directly.
    public bool IsWatching => _watcher?.IsRunning ?? false;

    public WatchStats? WatchStats => _watcher?.Stats;

    public void StartWatching()
    {
        if (!Settings.PriorityWatchEnabled)
        {
            Threats.SetWatchLine("Watch: off (enable it in Settings · Scans).");
            return;
        }

        EnsureWatcher();
        _watcher!.Start();
        _watchStartedUtc = DateTime.UtcNow;
        Threats.SetWatchLine(WatchLineForThreats());
    }

    public void Shutdown()
    {
        try
        {
            _watcher?.Stop();
        }
        catch
        {
        }

        try
        {
            _watcher?.Dispose();
        }
        catch
        {
        }

        _watcher = null;
    }

    private DateTime _watchStartedUtc = DateTime.UtcNow;

    private void ApplyWatchSetting()
    {
        if (Settings.PriorityWatchEnabled)
        {
            EnsureWatcher();
            _watcher!.Start();
            _watchStartedUtc = DateTime.UtcNow;
            Threats.SetWatchLine(WatchLineForThreats());
        }
        else
        {
            try
            {
                _watcher?.Stop();
            }
            catch
            {
            }

            Threats.SetWatchLine("Watch: off (enable it in Settings · Scans).");
        }
    }

    private void EnsureWatcher()
    {
        if (_watcher is not null)
        {
            return;
        }

        var watcher = _watcherFactory();
        watcher.CardPublished += OnWatchCard;
        watcher.DeltaReady += OnWatchDelta;
        _watcher = watcher;
    }

    private void OnWatchCard(WatchCard card)
    {
        _dispatcher.Post(() =>
        {
            Threats.AddWatchCard(card);
            Threats.SetWatchLine(WatchLineForThreats());
        });
    }

    // Priority lane first, bounded delta second (P21 acceptance):
    // a running/paused scan absorbs the paths live; otherwise one
    // small Balanced-10 delta runs when the session is free. Eco is
    // deliberately NOT used: Eco refuses on unknown power state
    // (A10), which would silently disable deltas on desktops.
    private void OnWatchDelta(IReadOnlyList<string> paths)
    {
        if (Session.State is ScanSessionState.Running or ScanSessionState.Paused)
        {
            int inserted = 0;
            foreach (var path in paths)
            {
                if (Session.TryEnqueuePriority(path))
                {
                    inserted++;
                }
            }

            _lastDeltaNote = $"{inserted}/{paths.Count} into the running scan";
            return;
        }

        if (!Session.CanStart)
        {
            _lastDeltaNote = "skipped (scan busy)";
            return;
        }

        if (Interlocked.CompareExchange(ref _deltaRunning, 1, 0) != 0)
        {
            _lastDeltaNote = "skipped (delta busy)";
            return;
        }

        var batch = paths.ToList();
        _ = Task.Run(async () =>
        {
            try
            {
                using var db = _dbFactory();
                var orchestrator = new ScanOrchestrator(db, neverTouch: Settings.NeverTouch);
                var roots = batch
                    .Select(p => { try { return Path.GetDirectoryName(p); } catch { return null; } })
                    .Where(d => !string.IsNullOrEmpty(d))
                    .Select(d => d!)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
                IReadOnlyList<string> finalRoots = roots.Count == 0 ? ["delta"] : roots;
                var result = await orchestrator.RescanPathsAsync(
                    batch,
                    new ScanOptions(
                        ScanMode.Balanced,
                        finalRoots,
                        balancedCapPercent: 10,
                        excludedPathPrefixes: ScanSessionViewModel.DefaultExclusions()),
                    new PauseToken()).ConfigureAwait(false);
                _lastDeltaNote = result.Outcome == ScanOutcome.Completed
                    ? $"{result.FilesSeen} paths, gen {result.Generation}"
                    : "delta " + result.Outcome.ToString().ToLowerInvariant();
            }
            catch (Exception ex)
            {
                _lastDeltaNote = "failed: " + ex.GetType().Name;
            }
            finally
            {
                Interlocked.Exchange(ref _deltaRunning, 0);
            }
        });
    }

    private string WatchLineForStatus()
    {
        var watcher = _watcher;
        if (watcher is null || !Settings.PriorityWatchEnabled || !watcher.IsRunning)
        {
            return "Watch: off";
        }

        var stats = watcher.Stats;
        double wallMs = Math.Max(1.0, (DateTime.UtcNow - _watchStartedUtc).TotalMilliseconds);
        double active = stats.ActiveMs / wallMs * 100.0;
        return $"Watch: on · {stats.CardsPublished} new · {active:F1}% active";
    }

    private string WatchLineForThreats()
    {
        var watcher = _watcher;
        if (watcher is null || !Settings.PriorityWatchEnabled || !watcher.IsRunning)
        {
            return "Watch: off (enable it in Settings · Scans).";
        }

        var stats = watcher.Stats;
        string delta = string.IsNullOrEmpty(_lastDeltaNote) ? "no delta yet" : "delta: " + _lastDeltaNote;
        return $"Watch: on · {stats.CardsPublished} new since opened · " +
            $"{stats.Coalesced} similar folded · {stats.ExcludedSkipped} excluded skipped · {delta}.";
    }

    // U27: recent agent findings + investigation history for Ask
    // grounding, pre-redacted + pre-truncated. Bounded: 5 newest
    // investigations, 10 findings each, 200 chars per observation.
    // Pure over the store (public static for tests); the caller
    // degrades to empty on failure.
    public static (IReadOnlyList<AskFindingDigest> Findings, string History) BuildAskDigests(
        AgentStore agent)
    {
        var digests = new List<AskFindingDigest>();
        var history = new StringBuilder();
        int number = 0;
        foreach (var inv in agent.ListInvestigations(5))
        {
            int count = 0;
            foreach (var finding in agent.GetFindings(inv.Id).Take(10))
            {
                number++;
                count++;
                string obs = SecretRedactor.RedactSecrets(
                    SecretRedactor.RedactUserPrefix(finding.Observation));
                if (obs.Length > 200)
                {
                    obs = obs[..200] + "…";
                }

                digests.Add(new AskFindingDigest(
                    number, finding.Status, obs, CitationNames(finding.EvidenceIdsJson)));
            }

            string goal = inv.Goal.Length > 80 ? inv.Goal[..80] + "…" : inv.Goal;
            history.Append(CultureInfo.InvariantCulture,
                $"- {goal} ({inv.Status}, {count} findings)\n");
        }

        return (digests, history.ToString());
    }

    // File names only from a finding's evidence JSON, redacted;
    // corrupt lists say so (mirrors HistoryViewModel.FormatCitations
    // minus the label — kept local, no App-internal coupling).
    private static string CitationNames(string evidenceIdsJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(evidenceIdsJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Array)
            {
                return "evidence list unreadable";
            }

            var names = new List<string>();
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                string path = el.TryGetProperty("path", out var p)
                    && p.ValueKind == JsonValueKind.String
                    ? p.GetString() ?? string.Empty
                    : string.Empty;
                string name = Path.GetFileName(path);
                names.Add(SecretRedactor.RedactUserPrefix(
                    string.IsNullOrEmpty(name) ? "(unnamed)" : name));
            }

            return names.Count == 0 ? "no evidence cited" : string.Join(", ", names);
        }
        catch (JsonException)
        {
            return "evidence list unreadable";
        }
    }

    // Live Ask context: last finished scan, recent crash cards, and
    // Defender state. All reads are bounded; failures degrade to
    // null/empty (the engine reports that honestly). Runs on a
    // background thread via the panel's Submit path.
    private AskContext BuildAskContext()
    {
        ScanSummary? last = Session.LastResult is { } r
            ? new ScanSummary(
                r.FilesSeen, r.BytesSeen, r.Gaps.Count, r.Generation,
                Session.LastRoot, r.Outcome.ToString(), r.Duration.TotalSeconds)
            : null;

        var crashes = new List<CrashCard>();
        try
        {
            var events = EventCollector.CollectTargeted(
                "System", null, 2, DateTime.UtcNow.AddDays(-7), 30);
            var anchors = events.Records
                .Where(e => e.Id is 1001 or 41 or 6008 or 1000 or 1002 or 55 or 153)
                .OrderByDescending(e => e.TimeUtc)
                .Take(5)
                .ToList();
            foreach (var anchor in anchors)
            {
                crashes.Add(CrashExplainer.Explain(anchor, events.Records));
            }
        }
        catch
        {
            // Degraded context: the engine says "no crashes found".
        }

        DefenderStatusRecord? defender = null;
        try
        {
            defender = DefenderCollector.CollectStatus().Records.FirstOrDefault();
        }
        catch
        {
            // Degraded context: the engine reports status unknown.
        }

        IReadOnlyList<AskFindingDigest> digests = [];
        string history = string.Empty;
        try
        {
            using var agent = new AgentStore(SentinelPaths.AgentDatabasePath);
            (digests, history) = BuildAskDigests(agent);
        }
        catch
        {
            // Degraded context: cloud answers ground in less.
        }

        return new AskContext(last, crashes, defender, KnowledgePack.PackVersion, digests, history);
    }
}
