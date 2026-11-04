using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using Sentinel.App.Services;
using Sentinel.Engine.Scan;
using Sentinel.Engine.SystemInventory;
using Sentinel.Store;

namespace Sentinel.App.ViewModels;

// P27: Cpu is "% of total machine capacity over a 250ms sample".
// "—" means the process exited or was protected on resample.
public sealed record ProcessRow(string Name, int Id, string Memory, string Company, string Cpu = "—");

public sealed record StartupRow(
    string Name, string Location, string Command, string Publisher, string State)
{
    // Observed impact is not measured (02 §11): the column
    // says so on every row, board-literal and honest.
    public string Impact => "Not measured";
}

public sealed record BatteryCard(string Title, string Charge, string Detail);

public sealed record DiskCard(
    string Name, string Sub, string Health, string Operational, bool Attention);

public sealed record GraphPoint(DateTime AtUtc, double CpuPercent, double RamMb);

// P27: one volume's free-space trend line ("C:: 24.5 → 24.1 GB
// free (7 days)"). Drive keys come from stored history, so a
// volume appears only once it has at least one sample.
public sealed record DriveTrendLine(string Drive, string Line);

// P27: everything that needs a store or a session. The static
// Collect stays pure over (history, extras); the instance
// CollectNow builds extras from its producers. Default keeps
// producer-less tests and factory-less construction working.
public sealed record PerformanceExtras(
    string ScanCost,
    IReadOnlyList<DriveTrendLine> DriveTrends,
    string CrashTrend)
{
    public static readonly PerformanceExtras Default = new(
        "No scan has run yet.",
        [],
        "No crash history yet.");
}

// Performance page (02 §11, board 03, read-only): top
// processes, startup programs with enable state, battery +
// disk cards, and Sentinel's own sampled resource history.
// Impact is honestly "Not measured"; I/O reads "No data" —
// both match the board's own honesty.
public sealed class PerformanceViewModel : ViewModelBase
{
    // A09: versions navigation collects; faults surface here
    // with the last graphs kept.
    public RefreshTracker RefreshState { get; } = new();

    private const int TopProcesses = 25;
    private const int MaxGraphPoints = 300;

    // Plain {Binding} cannot see static members; the range ComboBox
    // binds the instance passthrough (same A02 VM blank-control fix
    // as the Storage chips).
    public static readonly IReadOnlyList<string> RangeNames =
        ["Last 5 minutes", "Last 15 minutes", "Last 30 minutes"];

    public IReadOnlyList<string> Ranges => RangeNames;

    public Action<int>? NavigateToPage { get; set; }

    public ObservableCollection<ProcessRow> Processes { get; } = [];

    public ObservableCollection<StartupRow> StartupItems { get; } = [];

    public ObservableCollection<DiskCard> DiskCards { get; } = [];

    private IReadOnlyList<GraphPoint> _graphPoints = [];
    public IReadOnlyList<GraphPoint> GraphPoints
    {
        get => _graphPoints;
        private set => Set(ref _graphPoints, value);
    }

    private string _liveBattery = "Reading battery charge…";
    public string LiveBattery
    {
        get => _liveBattery;
        private set => Set(ref _liveBattery, value);
    }

    private string _systemMemory = "Reading PC memory…";
    public string SystemMemory
    {
        get => _systemMemory;
        private set => Set(ref _systemMemory, value);
    }

    public void UpdateLiveTelemetry(PowerState power, IReadOnlyList<ResourceSample> history)
    {
        LiveBattery = LiveTelemetry.BatteryLine(power);
        SystemMemory = LiveTelemetry.ReadSystemMemory();
        UpdateResources(history);
    }

    private IReadOnlyList<ResourceSample> _history = [];

    private string _battery = "—";

    public string Battery
    {
        get => _battery;
        private set => Set(ref _battery, value);
    }

    private string _disks = "—";

    public string Disks
    {
        get => _disks;
        private set => Set(ref _disks, value);
    }

    private string _coverage = string.Empty;

    // Visible coverage line: which sources failed or were partial.
    public string Coverage
    {
        get => _coverage;
        private set => Set(ref _coverage, value);
    }

    private string _machineLine = string.Empty;

    public string MachineLine
    {
        get => _machineLine;
        private set => Set(ref _machineLine, value);
    }

    private BatteryCard? _batteryCard;

    public BatteryCard? BatteryCard
    {
        get => _batteryCard;
        private set => Set(ref _batteryCard, value);
    }

    private string _batteryEmpty = "No battery device on this machine.";

    public string BatteryEmpty
    {
        get => _batteryEmpty;
        private set => Set(ref _batteryEmpty, value);
    }

    private string _selectedRange = RangeNames[0];

    public string SelectedRange
    {
        get => _selectedRange;
        set
        {
            if (Set(ref _selectedRange, value))
            {
                Reslice();
            }
        }
    }

    private string _cpuNow = "—";

    public string CpuNow
    {
        get => _cpuNow;
        private set => Set(ref _cpuNow, value);
    }

    private string _memoryNow = "—";

    public string MemoryNow
    {
        get => _memoryNow;
        private set => Set(ref _memoryNow, value);
    }

    private string _ioNow = "—";

    // P27: session IO from the latest sample ("Read 12 MB ·
    // Wrote 3 MB"). "—" until the first sample lands.
    public string IoNow
    {
        get => _ioNow;
        private set => Set(ref _ioNow, value);
    }

    private string _scanCostLine = PerformanceExtras.Default.ScanCost;

    public string ScanCost
    {
        get => _scanCostLine;
        private set => Set(ref _scanCostLine, value);
    }

    public ObservableCollection<DriveTrendLine> DriveTrends { get; } = [];

    private string _crashTrend = PerformanceExtras.Default.CrashTrend;

    public string CrashTrend
    {
        get => _crashTrend;
        private set => Set(ref _crashTrend, value);
    }

    // D45: measured boot context for the startup tab.
    private string _bootLine = string.Empty;

    public string BootLine
    {
        get => _bootLine;
        private set => Set(ref _bootLine, value);
    }

    // P27: last producer failure (store or scan-cost), cleared on
    // the next success. Producers never throw out of a refresh.
    private string? _lastPersistError;

    public string? LastPersistError
    {
        get => _lastPersistError;
        private set => Set(ref _lastPersistError, value);
    }

    public RelayCommand OpenDriversCommand { get; }

    private readonly Func<PassportDb>? _passportFactory;
    private readonly Func<string>? _scanCostProvider;

    public PerformanceViewModel(Func<PassportDb>? passportFactory = null, Func<string>? scanCost = null)
    {
        _passportFactory = passportFactory;
        _scanCostProvider = scanCost;
        OpenDriversCommand = new RelayCommand(_ => NavigateToPage?.Invoke(3));
    }

    public void Refresh() => Apply(CollectNow([]));

    // History snapshots on the UI thread (StatusBar owns the
    // buffer); Collect itself may run anywhere.
    public static PerformanceSnapshot Collect(
        IReadOnlyList<ResourceSample> history, PerformanceExtras? extras = null)
    {
        var processes = ProcessCollector.Collect();
        var runKeys = StartupCollector.CollectRunKeys();
        var folders = StartupCollector.CollectStartupFolders();
        var batteries = PowerCollector.CollectBatteries();
        var disks = PowerCollector.CollectDisks();
        // P27: sampled CPU% for the same top-N (one 250ms window,
        // page cadence only). Never throws out of the page.
        IReadOnlyDictionary<int, double?> cpu;
        try
        {
            cpu = ProcessCollector.CollectTopCpu(TopProcesses)
                .ToDictionary(s => s.Id, s => s.CpuPercent);
        }
        catch
        {
            cpu = new Dictionary<int, double?>();
        }

        // D45: measured boot context for the startup tab (tick
        // counter — no WMI, no admin, never throws).
        var boot = BootCollector.Collect();
        var rows = processes.Records
            .OrderByDescending(p => p.WorkingSetBytes)
            .Take(TopProcesses)
            .Select(p => new ProcessRow(
                p.Name,
                p.Id,
                $"{p.WorkingSetBytes / 1024.0 / 1024.0:F0} MB",
                string.IsNullOrWhiteSpace(p.Company) ? "—" : p.Company,
                cpu.TryGetValue(p.Id, out double? pct) && pct is not null ? $"{pct:F1}%" : "—"))
            .ToList();
        var startup = runKeys.Records
            .Concat(folders.Records)
            .Select(s => new StartupRow(
                s.Name, s.Location, s.Command,
                PublisherFor(s.Command),
                s.Enabled is null ? "Unknown" : s.Enabled.Value ? "Enabled" : "Disabled"))
            .ToList();
        string battery = batteries.Status == CollectionStatus.Failed
            ? $"Battery could not be inspected ({FirstReason(batteries)})."
            : batteries.Records.Count == 0
                ? "No battery device on this machine."
                : string.Join("; ", batteries.Records.Select(b =>
                    $"{b.Name}: {b.ChargePercent?.ToString() ?? "?"}% ({b.Status ?? "unknown status"})"));
        BatteryCard? card = batteries.Status == CollectionStatus.Success && batteries.Records.Count > 0
            ? BuildBatteryCard(batteries.Records[0])
            : null;
        string batteryEmpty = batteries.Status == CollectionStatus.Failed
            ? $"Battery could not be inspected ({FirstReason(batteries)})."
            : "No battery device on this machine.";
        string diskText = disks.Status == CollectionStatus.Failed
            ? $"Disks could not be inspected ({FirstReason(disks)})."
            : disks.Records.Count == 0
                ? "No disks reported."
                : string.Join("; ", disks.Records.Select(d =>
                    $"{d.Name} [{d.MediaType}]: {d.HealthStatus} / {d.OperationalStatus}"));
        var cards = disks.Records
            .Select(d => new DiskCard(
                d.Name,
                string.IsNullOrWhiteSpace(d.MediaType) ? "Unknown media" : d.MediaType,
                string.IsNullOrWhiteSpace(d.HealthStatus) ? "Unknown" : d.HealthStatus,
                string.IsNullOrWhiteSpace(d.OperationalStatus) ? "Unknown" : d.OperationalStatus,
                !string.Equals(d.HealthStatus, "Healthy", StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(d.HealthStatus, "Normal", StringComparison.OrdinalIgnoreCase)
                    && !string.IsNullOrWhiteSpace(d.HealthStatus)))
            .ToList();

        var problems = new List<string>();
        void Note<T>(string label, CollectionResult<T> r)
        {
            if (r.Status != CollectionStatus.Success)
            {
                problems.Add($"{label}: {r.Status} ({FirstReason(r)})");
            }
        }

        Note("Processes", processes);
        Note("Run keys", runKeys);
        Note("Startup folders", folders);
        Note("Battery", batteries);
        Note("Disks", disks);
        if (boot.Gap is not null)
        {
            problems.Add($"Boot time: {boot.Gap}");
        }

        var ex = extras ?? PerformanceExtras.Default;
        return new PerformanceSnapshot(
            rows, startup, battery, diskText,
            problems.Count == 0 ? "All sources inspected." : "Coverage: " + string.Join("; ", problems),
            card, batteryEmpty, cards, history.ToList(),
            ex.ScanCost, ex.DriveTrends, ex.CrashTrend,
            BootCollector.RenderLine(boot));
    }

    // P27: instance collect — builds store/session extras, then the
    // pure static Collect. Each producer is guarded: a failed
    // store surfaces LastPersistError, never an exception.
    public PerformanceSnapshot CollectNow(IReadOnlyList<ResourceSample> history)
    {
        return Collect(history, BuildExtras());
    }

    private PerformanceExtras BuildExtras()
    {
        var fallback = PerformanceExtras.Default;
        string scanCost = fallback.ScanCost;
        if (_scanCostProvider is not null)
        {
            try
            {
                scanCost = _scanCostProvider();
            }
            catch (Exception ex)
            {
                LastPersistError = "scan cost: " + ex.GetType().Name;
            }
        }

        var trends = new List<DriveTrendLine>();
        string crashTrend = fallback.CrashTrend;
        if (_passportFactory is not null)
        {
            try
            {
                using var db = _passportFactory();
                DateTime now = DateTime.UtcNow;
                RecordDriveSamples(db, now);
                DateTime floor = now.AddDays(-30);
                foreach (string drive in db.QueryDriveKeys())
                {
                    var samples = db.QueryDriveTrend(drive, floor);
                    trends.Add(new DriveTrendLine(drive, FormatDriveTrend(drive, samples)));
                }

                crashTrend = FormatCrashTrend(db.QueryCrashTrend(4, now));
                LastPersistError = null;
            }
            catch (Exception ex)
            {
                LastPersistError = ex.GetType().Name;
            }
        }

        return new PerformanceExtras(scanCost, trends, crashTrend);
    }

    // P27: one free-space sample per fixed ready drive, skipped when
    // the newest sample is under an hour old. Per-drive guards: a
    // flapping USB enclosure must not fail the whole refresh.
    private void RecordDriveSamples(PassportDb db, DateTime now)
    {
        DriveInfo[] drives;
        try
        {
            drives = DriveInfo.GetDrives();
        }
        catch
        {
            return;
        }

        foreach (var drive in drives)
        {
            try
            {
                if (drive.DriveType != DriveType.Fixed || !drive.IsReady)
                {
                    continue;
                }

                string key = drive.Name.TrimEnd('\\');
                var latest = db.QueryDriveTrend(key, null, 1);
                if (latest.Count > 0
                    && DateTime.TryParse(
                        latest[0].ObservedUtc, null,
                        DateTimeStyles.RoundtripKind, out DateTime seen)
                    && (now - seen.ToUniversalTime()).TotalMinutes < 60)
                {
                    continue;
                }

                db.RecordDriveSample(key, now, drive.AvailableFreeSpace, drive.TotalSize);
            }
            catch (Exception ex)
            {
                LastPersistError = drive.Name + ": " + ex.GetType().Name;
            }
        }
    }

    // P27: first→last free-space delta over the sampled window.
    // Newest-first samples in; honest singles ("first reading")
    // when only one exists.
    public static string FormatDriveTrend(string drive, IReadOnlyList<DriveFreeSample> newestFirst)
    {
        if (newestFirst.Count == 0)
        {
            return $"{drive}: no history yet.";
        }

        var newest = newestFirst[0];
        if (newestFirst.Count == 1)
        {
            return $"{drive}: {Gb(newest.FreeBytes):F1} GB free (first reading just now).";
        }

        var oldest = newestFirst[newestFirst.Count - 1];
        double days = Math.Max(0, (ParseUtc(newest.ObservedUtc) - ParseUtc(oldest.ObservedUtc)).TotalDays);
        string span = days < 1 ? "today" : CountText.Of((long)Math.Round(days), "day");
        return $"{drive}: {Gb(oldest.FreeBytes):F1} → {Gb(newest.FreeBytes):F1} GB free ({span}).";
    }

    public static string FormatCrashTrend(IReadOnlyList<CrashWeek> oldestFirst)
    {
        int total = 0;
        foreach (var week in oldestFirst)
        {
            total += week.Total;
        }

        if (total == 0)
        {
            return "No crashes recorded in the last 4 weeks.";
        }

        int thisWeek = oldestFirst.Count == 0 ? 0 : oldestFirst[oldestFirst.Count - 1].Total;
        string line = $"{CountText.Of(total, "crash", "crashes")} recorded in the last 4 weeks";
        return thisWeek > 0 ? $"{line} ({thisWeek} this week)." : line + ".";
    }

    // P27: the last scan's measured cost. Refused/failed runs say
    // why instead of showing zero-cost fiction.
    public static string FormatScanCost(OrchestratedScanResult? result, string root)
    {
        if (result is null)
        {
            return "No scan has run yet.";
        }

        if (result.Outcome != ScanOutcome.Completed)
        {
            string reason = result.RefusalReason ?? result.Error ?? root;
            return $"Last scan {result.Outcome}: {reason}.";
        }

        return $"{CountText.Of(result.FilesSeen, "file")} · {Gb(result.BytesSeen):F1} GB in " +
            $"{result.Duration.TotalSeconds:F1}s · {root} · Completed.";
    }

    public static string FormatIo(double readMb, double writeMb)
    {
        return $"Read {readMb:F0} MB · Wrote {writeMb:F0} MB";
    }

    private static double Gb(long bytes) => bytes / 1024.0 / 1024.0 / 1024.0;

    private static DateTime ParseUtc(string stamp)
    {
        return DateTime.TryParse(stamp, null, DateTimeStyles.RoundtripKind, out DateTime when)
            ? when.ToUniversalTime()
            : DateTime.UtcNow;
    }

    internal static BatteryCard BuildBatteryCard(BatteryRecord b)
    {
        string charge = b.ChargePercent is null ? "Charge unknown" : $"{b.ChargePercent}%";
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(b.Status))
        {
            parts.Add(b.Status);
        }

        if (b.DesignCapacityMWh is > 0 && b.FullChargedCapacityMWh is > 0)
        {
            parts.Add($"wear {100 - b.FullChargedCapacityMWh.Value * 100 / b.DesignCapacityMWh.Value}%");
        }

        if (b.CycleCount is > 0)
        {
            parts.Add($"{b.CycleCount} cycles");
        }

        return new BatteryCard(b.Name, charge, parts.Count == 0 ? "No further detail." : string.Join(" · ", parts));
    }

    // Publisher of the executable behind a startup command.
    // Unknown stays unknown — never guessed from the name.
    public static string PublisherFor(string command)
    {
        string? exe = ExtractExe(command);
        if (exe is null)
        {
            return "Unknown";
        }

        try
        {
            string resolved = exe;
            if (!Path.IsPathRooted(resolved))
            {
                string system32 = Path.Combine(Environment.SystemDirectory, resolved);
                string windows = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows), resolved);
                resolved = File.Exists(system32) ? system32
                    : File.Exists(windows) ? windows : resolved;
            }

            if (!File.Exists(resolved))
            {
                return "Unknown";
            }

            string? company = FileVersionInfo.GetVersionInfo(resolved).CompanyName;
            return string.IsNullOrWhiteSpace(company) ? "Unknown" : company.Trim();
        }
        catch
        {
            return "Unknown";
        }
    }

    internal static string? ExtractExe(string command)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return null;
        }

        string text = command.Trim();
        if (text.StartsWith('"'))
        {
            int end = text.IndexOf('"', 1);
            return end > 1 ? text[1..end] : null;
        }

        // Unquoted: executable is the first whitespace-delimited
        // token. rundll32-style hosts resolve to the host itself,
        // whose publisher is still honest to show.
        int space = text.IndexOfAny([' ', '\t']);
        string token = space < 0 ? text : text[..space];
        return token.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            || token.EndsWith(".com", StringComparison.OrdinalIgnoreCase)
            || token.EndsWith(".bat", StringComparison.OrdinalIgnoreCase)
            || token.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase)
            ? token
            : null;
    }

    // Newest-first slice, downsampled to the point cap by even
    // stride. Pure: same history + range always yields the same
    // points (tested).
    public static IReadOnlyList<GraphPoint> SliceHistory(
        IReadOnlyList<ResourceSample> history, string range, int maxPoints = MaxGraphPoints)
    {
        int minutes = range.StartsWith("Last 15", StringComparison.Ordinal) ? 15
            : range.StartsWith("Last 30", StringComparison.Ordinal) ? 30 : 5;
        if (history.Count == 0)
        {
            return [];
        }

        DateTime cutoff = history[history.Count - 1].AtUtc.AddMinutes(-minutes);
        var window = history.Where(s => s.AtUtc >= cutoff).ToList();
        if (window.Count == 0)
        {
            return [];
        }

        int stride = Math.Max(1, (int)Math.Ceiling((double)window.Count / Math.Max(1, maxPoints)));
        var points = new List<GraphPoint>();
        for (int i = 0; i < window.Count; i += stride)
        {
            points.Add(new GraphPoint(window[i].AtUtc, window[i].CpuPercent, window[i].RamMb));
        }

        if ((window.Count - 1) % stride != 0)
        {
            var last = window[window.Count - 1];
            points.Add(new GraphPoint(last.AtUtc, last.CpuPercent, last.RamMb));
        }

        return points;
    }

    public void Apply(PerformanceSnapshot s)
    {
        Processes.Clear();
        foreach (var row in s.Processes)
        {
            Processes.Add(row);
        }

        StartupItems.Clear();
        foreach (var row in s.Startup)
        {
            StartupItems.Add(row);
        }

        DiskCards.Clear();
        foreach (var card in s.DiskCards)
        {
            DiskCards.Add(card);
        }

        Battery = s.Battery;
        Disks = s.Disks;
        Coverage = s.Coverage;
        MachineLine = BuildMachineLine();
        BatteryCard = s.BatteryCard;
        BatteryEmpty = s.BatteryEmpty;
        ScanCost = s.ScanCost;
        DriveTrends.Clear();
        if (s.DriveTrends is not null)
        {
            foreach (var trend in s.DriveTrends)
            {
                DriveTrends.Add(trend);
            }
        }

        CrashTrend = s.CrashTrend;
        BootLine = s.BootLine;
        UpdateResources(s.History);
        RefreshState.NoteSuccess();
    }

    private void UpdateResources(IReadOnlyList<ResourceSample> history)
    {
        _history = history;
        var latest = history.Count == 0 ? null : history[history.Count - 1];
        CpuNow = latest is null ? "—" : $"{latest.CpuPercent:F1}%";
        MemoryNow = latest is null ? "—" : $"{latest.RamMb:F0} MB";
        IoNow = latest is null ? "—" : FormatIo(latest.IoReadMb, latest.IoWriteMb);
        Reslice();
    }

    private void Reslice()
    {
        GraphPoints = SliceHistory(_history, SelectedRange);
    }

    internal static string BuildMachineLine()
    {
        try
        {
            return $"{Environment.MachineName} · {Environment.OSVersion.VersionString}";
        }
        catch
        {
            return "This PC";
        }
    }

    private static string FirstReason<T>(CollectionResult<T> r)
    {
        return r.Gaps.Count == 0 ? "unknown reason" : r.Gaps[0].Reason;
    }

    public sealed record PerformanceSnapshot(
        IReadOnlyList<ProcessRow> Processes,
        IReadOnlyList<StartupRow> Startup,
        string Battery,
        string Disks,
        string Coverage,
        BatteryCard? BatteryCard,
        string BatteryEmpty,
        IReadOnlyList<DiskCard> DiskCards,
        IReadOnlyList<ResourceSample> History,
        string ScanCost = "No scan has run yet.",
        IReadOnlyList<DriveTrendLine>? DriveTrends = null,
        string CrashTrend = "No crash history yet.",
        string BootLine = "");
}
