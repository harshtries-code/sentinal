using System.Runtime.InteropServices;
using Sentinel.Engine.CrashDoctor;
using Sentinel.Engine.SystemInventory;
using Sentinel.Store;

namespace Sentinel.App.ViewModels;

// Overview dashboard (board 01-overview). Every number is live
// Phase 2 evidence: last scan run, cleaner tiers, device problems,
// detections, recent events, power, disk-warning clusters, and DB
// activity. Anything uninspectable renders its reason — the board's
// fixture values NEVER appear.
public sealed record OrganCard(
    string Title, string Detail, string Badge, int PageIndex, bool IsGood);

public sealed record ReviewFinding(
    string Title, string Subtitle, string Pill, string Module, int PageIndex);

public sealed record RelationCluster(
    string DeviceLabel, string DiskDetail, int EventCount,
    string NewestSummary, bool HasDiskMatch);

public sealed record CoverageRow(
    string Area, string Status, string Detail, int PageIndex, bool IsOk);

public sealed record ActivityRow(
    string Time, string Title, string Detail, bool IsGood);

public sealed class OverviewViewModel : ViewModelBase
{
    // A09: versions navigation collects; faults surface here
    // with the last hero kept.
    public RefreshTracker RefreshState { get; } = new();

    private readonly Func<SentinelDb> _dbFactory;
    private readonly Func<AgentStore> _agentFactory;
    private readonly Func<IReadOnlyList<string>> _neverTouch;

    public OverviewViewModel(
        Func<SentinelDb> dbFactory,
        Func<AgentStore> agentFactory,
        Func<IReadOnlyList<string>> neverTouch)
    {
        _dbFactory = dbFactory;
        _agentFactory = agentFactory;
        _neverTouch = neverTouch;
        OpenPageCommand = new RelayCommand(p =>
        {
            if (p is int index)
            {
                NavigateToPage?.Invoke(index);
            }
            else if (p is string text)
            {
                // U21: deep links carry scope ("page|scope") so the
                // target page shows which evidence you came from.
                // Plain numbers keep the old scope-less path.
                int bar = text.IndexOf('|');
                if (bar > 0
                    && int.TryParse(text.AsSpan(0, bar), out int scoped)
                    && bar + 1 < text.Length)
                {
                    NavigateWithScope?.Invoke(scoped, text.Substring(bar + 1));
                }
                else if (int.TryParse(text, out int parsed))
                {
                    NavigateToPage?.Invoke(parsed);
                }
            }
        });
        ZoomInCommand = new RelayCommand(_ => GraphZoom = Math.Min(2.0, GraphZoom + 0.25));
        ZoomOutCommand = new RelayCommand(_ => GraphZoom = Math.Max(0.5, GraphZoom - 0.25));
        ZoomResetCommand = new RelayCommand(_ => GraphZoom = 1.0);
        InspectClusterCommand = new RelayCommand(p =>
        {
            if (p is RelationCluster cluster)
            {
                SelectedCluster = cluster;
            }
        });
        MachineLine = BuildMachineLine();
    }

    // Wired by the shell: organ cards, findings, coverage, and
    // activity all navigate to real pages. Never a dead control.
    public Action<int>? NavigateToPage { get; set; }

    // U21: deep-link navigation with scope (the shell shows the
    // scope on the target page).
    public event Action<int, string>? NavigateWithScope;

    public RelayCommand OpenPageCommand { get; }

    public RelayCommand ZoomInCommand { get; }

    public RelayCommand ZoomOutCommand { get; }

    public RelayCommand ZoomResetCommand { get; }

    public RelayCommand InspectClusterCommand { get; }

    public string MachineLine { get; }

    private string _lastScanLine = "Last scan: —";
    private string _heroTitle = "Loading…";
    private string _heroDetail = string.Empty;
    private bool _heroIsOk;
    private IReadOnlyList<OrganCard> _organs = [];
    private IReadOnlyList<ReviewFinding> _findings = [];
    private IReadOnlyList<RelationCluster> _clusters = [];
    private bool _relationsGraphView = true;
    private IReadOnlyList<CoverageRow> _coverage = [];
    private IReadOnlyList<ActivityRow> _activity = [];

    public string LastScanLine
    {
        get => _lastScanLine;
        private set => Set(ref _lastScanLine, value);
    }

    public string HeroTitle
    {
        get => _heroTitle;
        private set => Set(ref _heroTitle, value);
    }

    public string HeroDetail
    {
        get => _heroDetail;
        private set => Set(ref _heroDetail, value);
    }

    public bool HeroIsOk
    {
        get => _heroIsOk;
        private set => Set(ref _heroIsOk, value);
    }

    public IReadOnlyList<OrganCard> Organs
    {
        get => _organs;
        private set => Set(ref _organs, value);
    }

    public IReadOnlyList<ReviewFinding> Findings
    {
        get => _findings;
        private set => Set(ref _findings, value);
    }

    public bool HasFindings => Findings.Count > 0;

    public IReadOnlyList<RelationCluster> Clusters
    {
        get => _clusters;
        private set => Set(ref _clusters, value);
    }

    public bool HasClusters => Clusters.Count > 0;

    public RelationCluster? FirstCluster => Clusters.Count > 0 ? Clusters[0] : null;

    public bool RelationsGraphView
    {
        get => _relationsGraphView;
        set => Set(ref _relationsGraphView, value);
    }

    private double _graphZoom = 1.0;

    // U21: evidence-graph zoom (0.5–2.0). Pan is the surrounding
    // ScrollViewer; both views stay keyboard-usable.
    public double GraphZoom
    {
        get => _graphZoom;
        set => Set(ref _graphZoom, Math.Clamp(value, 0.5, 2.0));
    }

    private RelationCluster? _selectedCluster;

    // U21: node inspection — set from graph nodes and list rows.
    // Cleared on every Apply; inspection never outlives its data.
    public RelationCluster? SelectedCluster
    {
        get => _selectedCluster;
        private set
        {
            if (Set(ref _selectedCluster, value))
            {
                Raise(nameof(SelectedClusterDetail));
                Raise(nameof(HasSelectedCluster));
            }
        }
    }

    public bool HasSelectedCluster => SelectedCluster is not null;

    public string SelectedClusterDetail => SelectedCluster is null
        ? string.Empty
        : $"{SelectedCluster.DeviceLabel} — {SelectedCluster.EventCount} disk events · " +
            $"{SelectedCluster.DiskDetail}. Newest: {SelectedCluster.NewestSummary} " +
            "(possible relationship, not a diagnosis).";

    public void SelectCluster(RelationCluster? cluster) => SelectedCluster = cluster;

    public IReadOnlyList<CoverageRow> Coverage
    {
        get => _coverage;
        private set => Set(ref _coverage, value);
    }

    public IReadOnlyList<ActivityRow> Activity
    {
        get => _activity;
        private set => Set(ref _activity, value);
    }

    public bool HasActivity => Activity.Count > 0;

    public void Refresh() => Apply(Collect());

    // Each area collects independently guarded: one failing source
    // degrades its own card/row, never the whole page.
    public OverviewSnapshot Collect()
    {
        var runKeys = Guard(() => StartupCollector.CollectRunKeys());
        var folders = Guard(() => StartupCollector.CollectStartupFolders());
        var drivers = Guard(() => DriverCollector.Collect());
        var problems = Guard(() => DriverCollector.CollectDeviceProblems());
        var events = Guard(() => EventCollector.CollectRecent(perLog: 50));
        var diskWarnings = Guard(() => EventCollector.CollectTargeted(
            "System", null, 3, DateTime.UtcNow.AddDays(-7), 200));
        var topology = Guard(() => DiskTopologyCollector.Collect());
        var batteries = Guard(() => PowerCollector.CollectBatteries());
        var disks = Guard(() => PowerCollector.CollectDisks());
        var defenderStatus = Guard(() => DefenderCollector.CollectStatus());
        var detections = Guard(() => DefenderCollector.CollectDetections(50));

        CleanerViewModel.CleanerSnapshot? cleaner = null;
        string? cleanerError = null;
        try
        {
            cleaner = CleanerViewModel.Collect(_dbFactory, _neverTouch());
        }
        catch (Exception ex)
        {
            cleanerError = ex.GetType().Name;
        }

        IReadOnlyList<ScanRunInfo> runs = [];
        try
        {
            using var db = _dbFactory();
            runs = db.ListRuns(5);
        }
        catch
        {
            // History stays empty; the hero says so honestly.
        }

        IReadOnlyList<InvestigationState> investigations = [];
        try
        {
            using var agent = _agentFactory();
            investigations = agent.ListInvestigations(5);
        }
        catch
        {
        }

        return new OverviewSnapshot(
            runKeys, folders, drivers, problems,
            events, diskWarnings, topology, batteries, disks,
            defenderStatus, detections, cleaner, cleanerError,
            runs, investigations);
    }

    public void Apply(OverviewSnapshot s)
    {
        var run = s.Runs.Count > 0 ? s.Runs[0] : null;
        if (run is null)
        {
            HeroTitle = "Never scanned";
            HeroDetail = "Run your first scan to inventory this PC.";
            HeroIsOk = false;
            LastScanLine = "Last scan: never";
        }
        else if (run.Status == "Completed")
        {
            HeroTitle = "Scan complete";
            HeroDetail = $"{CountText.Of(run.FilesSeen, "file")} inventoried" +
                (run.GapsCount > 0 ? $" · {CountText.Of(run.GapsCount, "location")} unavailable" : string.Empty);
            HeroIsOk = true;
            LastScanLine = FormatLastScan(run);
        }
        else
        {
            HeroTitle = $"Last scan {run.Status.ToLowerInvariant()}";
            HeroDetail = $"{CountText.Of(run.FilesSeen, "file")} seen before it stopped" +
                (!string.IsNullOrWhiteSpace(run.Error) ? $" — {run.Error}" : string.Empty);
            HeroIsOk = false;
            LastScanLine = FormatLastScan(run);
        }

        Organs = BuildOrgans(s);
        Findings = BuildFindings(s);
        Raise(nameof(HasFindings));
        Clusters = BuildClusters(s.DiskWarnings.Records, s.Topology.Records);
        Raise(nameof(HasClusters));
        Raise(nameof(FirstCluster));
        SelectCluster(null);
        Coverage = BuildCoverage(s);
        Activity = BuildActivity(s.Runs, s.Investigations);
        Raise(nameof(HasActivity));
        RefreshState.NoteSuccess();
    }

    private static CollectionResult<T> Guard<T>(Func<CollectionResult<T>> collect)
    {
        try
        {
            return collect();
        }
        catch (Exception ex)
        {
            return CollectionResult<T>.Fail("overview", ex.GetType().Name);
        }
    }

    public static IReadOnlyList<OrganCard> BuildOrgans(OverviewSnapshot s)
    {
        string storage;
        bool storageOk = true;
        if (s.Cleaner is null)
        {
            storage = "Couldn't inspect storage";
            storageOk = false;
        }
        else
        {
            long review = 0;
            foreach (var tier in s.Cleaner.Tiers)
            {
                if (tier.Tier == "REVIEW")
                {
                    review = tier.BytesRaw;
                }
            }

            storage = review > 0 ? $"{FormatBytes(review)} to review" : "Nothing flagged to review";
        }

        string drivers;
        bool driversOk;
        if (s.Problems.Status == CollectionStatus.Failed)
        {
            drivers = "Couldn't inspect devices";
            driversOk = false;
        }
        else
        {
            int n = s.Problems.Records.Count;
            drivers = n == 0 ? "No device problems" : $"{n} device problem{(n == 1 ? string.Empty : "s")}";
            driversOk = n == 0;
        }

        string startup;
        bool startupOk = true;
        if (s.RunKeys.Status == CollectionStatus.Failed
            && s.StartupFolders.Status == CollectionStatus.Failed)
        {
            startup = "Couldn't inspect startup";
            startupOk = false;
        }
        else
        {
            int n = s.RunKeys.Records.Count + s.StartupFolders.Records.Count;
            startup = $"{n} startup {(n == 1 ? "entry" : "entries")}";
        }

        string threats;
        bool threatsOk;
        if (s.Detections.Status == CollectionStatus.Failed)
        {
            threats = "Defender history unavailable";
            threatsOk = false;
        }
        else
        {
            int n = s.Detections.Records.Count;
            threats = $"{n} detection{(n == 1 ? string.Empty : "s")} reported";
            threatsOk = n == 0;
        }

        string stability;
        bool stabilityOk = true;
        if (s.Events.Status == CollectionStatus.Failed)
        {
            stability = "Event log unavailable";
            stabilityOk = false;
        }
        else
        {
            int n = s.Events.Records.Count;
            stability = n == 0 ? "No recent errors" : $"{n} relevant events";
            stabilityOk = n == 0;
        }

        string power;
        bool powerOk = true;
        if (s.Batteries.Status == CollectionStatus.Failed)
        {
            power = "Power info unavailable";
            powerOk = false;
        }
        else if (s.Batteries.Records.Count == 0)
        {
            power = "No battery device";
        }
        else
        {
            power = $"Battery {s.Batteries.Records[0].ChargePercent?.ToString() ?? "?"}%";
        }

        return
        [
            new OrganCard("Storage", storage, "S", 2, storageOk),
            new OrganCard("Drivers", drivers, "D", 3, driversOk),
            new OrganCard("Startup", startup, "P", 1, startupOk),
            new OrganCard("Threats", threats, "T", 4, threatsOk),
            new OrganCard("Stability", stability, "!", 5, stabilityOk),
            new OrganCard("Power", power, "W", 1, powerOk),
        ];
    }

    public static IReadOnlyList<ReviewFinding> BuildFindings(OverviewSnapshot s)
    {
        var findings = new List<ReviewFinding>();
        if (s.Cleaner is not null)
        {
            foreach (var item in s.Cleaner.TopReview.Take(2))
            {
                findings.Add(new ReviewFinding(
                    TrimMiddle(item.Path, 64), item.Reasons, item.Size, "Storage", 2));
            }
        }

        if (s.Problems.Status != CollectionStatus.Failed)
        {
            foreach (var problem in s.Problems.Records.Take(2))
            {
                findings.Add(new ReviewFinding(
                    problem.Name, problem.ErrorName,
                    "Code " + problem.ErrorCode, "Drivers", 3));
            }
        }

        if (s.Detections.Status != CollectionStatus.Failed
            && s.Detections.Records.Count > 0)
        {
            var det = s.Detections.Records[0];
            findings.Add(new ReviewFinding(
                det.ThreatName, det.Severity, "Detection", "Threats", 4));
        }
        else if (s.Events.Status != CollectionStatus.Failed
            && s.Events.Records.Count > 0)
        {
            var ev = s.Events.Records[0];
            findings.Add(new ReviewFinding(
                $"Event {ev.Id} in {ev.Log}", ev.Provider, ev.Level, "Stability", 5));
        }

        // U21: top-three review priorities, highest-signal first.
        return findings.Take(3).ToList();
    }

    // U21: last scan with mode and duration. Unknown mode and
    // zero duration are omitted, never printed as fiction.
    public static string FormatLastScan(ScanRunInfo run)
    {
        var parts = new List<string> { "Last scan: " + ToLocalTime(run.StartedUtc) };
        if (!string.IsNullOrWhiteSpace(run.Mode)
            && !string.Equals(run.Mode, "Unknown", StringComparison.OrdinalIgnoreCase))
        {
            parts.Add(run.Mode);
        }

        if (run.DurationMs > 0)
        {
            parts.Add($"{run.DurationMs / 1000.0:F1}s");
        }

        return string.Join(" · ", parts);
    }

    // Disk-warning clusters: 153/55 events grouped by the device
    // they name (same anchored tokens as P2-03). A cluster is a
    // POSSIBLE relationship — the UI must always label it so and
    // never draw it as confirmed.
    public static IReadOnlyList<RelationCluster> BuildClusters(
        IReadOnlyList<TargetedEventRecord> warnings,
        IReadOnlyList<DiskTopologyRecord> topology)
    {
        var hits = warnings.Where(CrashExplainer.IsDiskWarning).ToList();
        var groups = new Dictionary<string, List<TargetedEventRecord>>(StringComparer.Ordinal);
        foreach (var hit in hits)
        {
            var tokens = CrashExplainer.ParseDeviceTokens(
                hit.Message + " " + string.Join(" ", hit.Properties));
            string key = tokens.Count > 0
                ? tokens.OrderBy(t => t, StringComparer.Ordinal).First()
                : "unknown device";
            if (!groups.TryGetValue(key, out var list))
            {
                list = [];
                groups[key] = list;
            }

            list.Add(hit);
        }

        return groups
            .OrderByDescending(g => g.Value.Count)
            .Take(5)
            .Select(g =>
            {
                var newest = g.Value.OrderByDescending(e => e.TimeUtc).First();
                var disk = MatchDisk(g.Key, topology);
                string diskDetail = disk is null
                    ? "Device not in current disk inventory"
                    : $"{disk.Name} · {FormatBytes(disk.SizeBytes ?? 0)}";
                return new RelationCluster(
                    g.Key == "unknown device" ? "Unidentified device" : g.Key,
                    diskDetail, g.Value.Count,
                    $"Event {newest.Id} · {ToLocalTime(newest.TimeUtc)}",
                    disk is not null);
            })
            .ToList();
    }

    private static DiskTopologyRecord? MatchDisk(
        string token, IReadOnlyList<DiskTopologyRecord> topology)
    {
        foreach (var disk in topology)
        {
            if (token.Contains($"DISK {disk.DiskNumber}", StringComparison.Ordinal)
                || token.Contains($"HARDDISK{disk.DiskNumber}", StringComparison.Ordinal))
            {
                return disk;
            }
        }

        return null;
    }

    public static IReadOnlyList<CoverageRow> BuildCoverage(OverviewSnapshot s)
    {
        return
        [
            Cover("Storage",
                s.Cleaner is null ? CollectionStatus.Failed : CollectionStatus.Success,
                s.Cleaner is null ? s.CleanerError ?? "Read failed" : $"{CountText.Of(s.Cleaner.TotalFiles, "file")} classified", 2),
            Cover("Drivers", Worst(s.Drivers.Status, s.Problems.Status),
                $"{CountText.Of(s.Problems.Records.Count, "problem")} · {CountText.Of(s.Drivers.Records.Count, "driver")}", 3),
            Cover("Startup", Worst(s.RunKeys.Status, s.StartupFolders.Status),
                $"{CountText.Of(s.RunKeys.Records.Count + s.StartupFolders.Records.Count, "entry", "entries")}", 1),
            Cover("Defender", Worst(s.DefenderStatus.Status, s.Detections.Status),
                $"{s.Detections.Records.Count} on record", 4),
            Cover("Events", s.Events.Status,
                $"{s.Events.Records.Count} recent", 5),
            Cover("Power", Worst(s.Batteries.Status, s.Disks.Status),
                s.Batteries.Records.Count == 0 ? "No battery device" : $"{s.Batteries.Records.Count} batteries", 1),
        ];
    }

    private static CoverageRow Cover(
        string area, CollectionStatus status, string detail, int page)
    {
        return status switch
        {
            CollectionStatus.Success => new CoverageRow(area, "Complete", detail, page, true),
            CollectionStatus.Partial => new CoverageRow(area, "Partial", detail, page, true),
            _ => new CoverageRow(area, "Couldn't inspect", detail, page, false),
        };
    }

    private static CollectionStatus Worst(CollectionStatus a, CollectionStatus b)
    {
        if (a == CollectionStatus.Failed || b == CollectionStatus.Failed)
        {
            return CollectionStatus.Failed;
        }

        if (a == CollectionStatus.Partial || b == CollectionStatus.Partial)
        {
            return CollectionStatus.Partial;
        }

        return CollectionStatus.Success;
    }

    public static IReadOnlyList<ActivityRow> BuildActivity(
        IReadOnlyList<ScanRunInfo> runs,
        IReadOnlyList<InvestigationState> investigations)
    {
        var rows = new List<(DateTime At, ActivityRow Row)>();
        foreach (var run in runs)
        {
            bool ok = run.Status == "Completed";
            rows.Add((ParseUtc(run.StartedUtc), new ActivityRow(
                ToLocalTime(run.StartedUtc),
                ok ? "Scan completed" : $"Scan {run.Status.ToLowerInvariant()}",
                $"{CountText.Of(run.FilesSeen, "file")} inventoried · generation {run.Generation}" +
                    (run.GapsCount > 0 ? $" · {CountText.Of(run.GapsCount, "location")} unavailable" : string.Empty),
                ok)));
        }

        foreach (var inv in investigations)
        {
            bool ok = inv.Status is "Done" or "Completed";
            rows.Add((ParseUtc(inv.UpdatedUtc), new ActivityRow(
                ToLocalTime(inv.UpdatedUtc),
                $"Investigation {inv.Status.ToLowerInvariant()}",
                string.IsNullOrWhiteSpace(inv.Goal) ? "Storage scan" : TrimMiddle(inv.Goal, 60),
                ok)));
        }

        return rows
            .OrderByDescending(r => r.At)
            .Take(6)
            .Select(r => r.Row)
            .ToList();
    }

    private static string BuildMachineLine()
    {
        string machine;
        try
        {
            machine = Environment.MachineName;
        }
        catch
        {
            machine = "This PC";
        }

        return $"{machine} · {BuildOsShort()}";
    }

    private static string BuildOsShort()
    {
        try
        {
            var version = Environment.OSVersion.Version;
            if (OperatingSystem.IsWindows() && version.Build >= 22000)
            {
                return "Windows 11";
            }

            if (OperatingSystem.IsWindows())
            {
                return "Windows";
            }

            return RuntimeInformation.OSDescription;
        }
        catch
        {
            return "Windows";
        }
    }

    internal static string ToLocalTime(string utcText)
    {
        return ParseUtc(utcText).ToLocalTime().ToString("HH:mm");
    }

    internal static string ToLocalTime(DateTime utc)
    {
        var stamped = utc.Kind == DateTimeKind.Unspecified
            ? DateTime.SpecifyKind(utc, DateTimeKind.Utc)
            : utc;
        return stamped.ToLocalTime().ToString("HH:mm");
    }

    private static DateTime ParseUtc(string utcText)
    {
        if (DateTime.TryParse(
                utcText, null,
                System.Globalization.DateTimeStyles.RoundtripKind,
                out var parsed))
        {
            return parsed.Kind == DateTimeKind.Unspecified
                ? DateTime.SpecifyKind(parsed, DateTimeKind.Utc)
                : parsed.ToUniversalTime();
        }

        return DateTime.UtcNow;
    }

    internal static string TrimMiddle(string text, int max)
    {
        if (string.IsNullOrEmpty(text) || text.Length <= max)
        {
            return text;
        }

        int keep = (max - 1) / 2;
        return text[..keep] + "…" + text[^keep..];
    }

    internal static string FormatBytes(long bytes)
    {
        const long KB = 1024;
        const long MB = 1024 * 1024;
        const long GB = 1024L * 1024L * 1024L;
        if (bytes >= GB)
        {
            return $"{bytes / (double)GB:0.#} GB";
        }

        if (bytes >= MB)
        {
            return $"{bytes / (double)MB:0.#} MB";
        }

        if (bytes >= KB)
        {
            return $"{bytes / (double)KB:0.#} KB";
        }

        return $"{bytes} B";
    }

    public sealed record OverviewSnapshot(
        CollectionResult<StartupRecord> RunKeys,
        CollectionResult<StartupRecord> StartupFolders,
        CollectionResult<DriverRecord> Drivers,
        CollectionResult<DeviceProblemRecord> Problems,
        CollectionResult<EventRecord> Events,
        CollectionResult<TargetedEventRecord> DiskWarnings,
        CollectionResult<DiskTopologyRecord> Topology,
        CollectionResult<BatteryRecord> Batteries,
        CollectionResult<DiskHealthRecord> Disks,
        CollectionResult<DefenderStatusRecord> DefenderStatus,
        CollectionResult<DefenderDetectionRecord> Detections,
        CleanerViewModel.CleanerSnapshot? Cleaner,
        string? CleanerError,
        IReadOnlyList<ScanRunInfo> Runs,
        IReadOnlyList<InvestigationState> Investigations);
}
