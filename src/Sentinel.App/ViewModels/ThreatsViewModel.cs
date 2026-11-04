using System.Collections.ObjectModel;
using System.IO;
using Sentinel.Engine.Actions;
using Sentinel.Engine.SystemInventory;
using Sentinel.Engine.ThreatIntel;
using Sentinel.Engine.Watch;

namespace Sentinel.App.ViewModels;

public sealed record ThreatDetectionRow(
    string Threat, string Severity, string Path, string Detected, string Action, bool IsTest);

public sealed record ThreatProcessRow(
    string Name, string Path, string Company, string Memory,
    string Parent = "", int Id = 0);

// T51: Detail is OBSERVED (what/where); Suspicion is heuristic
// (a check-first note with a rule id, or empty). Suspicion never
// names malware — an unverified row is unverified, not guilty.
public sealed record PersistenceRow(
    string Type, string Name, string Detail, string Suspicion = "");

// T52: one CURRENT quarantine entry + its explanation. Rows come
// ONLY from the live quarantine list — never from old detection
// history (the history only explains a listed row).
public sealed record QuarantineRow(
    string Name, string Threat, string Resource, string Detected, string Explanation);

public sealed record DetectionEvidence(
    string HashDisplay, string SignedLine, string AvailabilityLine);

public sealed record FileCheckResult(
    string Title, string HashDisplay, string SignedLine, string SizeLine,
    // T53: grounded explanation of the local evidence + the
    // second-opinion boundary (always unavailable in v1).
    string Explanation = "", string SecondOpinion = "");

// P21: one rendered watch card. Plain language + evidence, never a
// malware claim (the M4 vocabulary: Unverified is an observation).
public sealed record WatchCardRow(
    string Time, string Name, string Verdict, string Detail, string Source);

// Threats page (02 §9, board 05): Defender's own state and
// detections (with on-demand local static evidence), the process
// triage table, startup persistence, the quarantine view, and a
// check-a-file card — plus, since T50, confirmed Defender scans
// through the defender_scan template (the A03 containment is
// lifted for the executor/Confirm path only). Quarantine restore
// and removals need their planned executor and have no controls
// here. Sentinel AI never removes files.
public sealed class ThreatsViewModel : ViewModelBase
{
    // T51 suspicion vocabulary: every note carries a rule id and
    // NEVER names malware (pinned by test — an unverified row is
    // unverified, not guilty).
    internal const string SuspicionExtensionContent =
        "H-ext-content: can read page content — check why it needs to.";
    internal const string SuspicionWmiBinding =
        "H-wmi-binding: event subscriptions are rare — verify this one belongs here.";
    internal const string SuspicionTaskHidden =
        "H-task-hidden: hidden from the default Task Scheduler view — verify it belongs.";

    private readonly ThreatActionServices? _actions;

    // T50: actions wires scan confirmation; null keeps the
    // plan-only notes (honestly read-only).
    public ThreatsViewModel(ThreatActionServices? actions = null)
    {
        _actions = actions;
    }

    public bool ScanActionsAvailable => _actions is not null;

    public bool RestoreActionsAvailable => _actions?.QuarantineHost is not null;

    // A09: versions the page-collect channel. Selection
    // hashes and file checks have their own gates below: a
    // detail read must never invalidate a page collect (or
    // vice versa) — only Apply resets all three.
    public RefreshTracker RefreshState { get; } = new();

    private readonly AsyncGate _evidenceGate = new();
    private readonly AsyncGate _fileCheckGate = new();
    private readonly AsyncGate _processGate = new();
    private readonly AsyncGate _persistenceGate = new();

    public long BeginDetectionEvidence() => _evidenceGate.Next();

    public long BeginFileCheck() => _fileCheckGate.Next();

    public long BeginProcessDetail() => _processGate.Next();

    public long BeginPersistenceDetail() => _persistenceGate.Next();

    public ObservableCollection<ThreatDetectionRow> Detections { get; } = [];

    // U24: filtered detection timeline — severity picker plus
    // threat/path search. Detections stays the unfiltered truth;
    // the grid binds FilteredDetections.
    public IReadOnlyList<string> SeverityOptions { get; } =
        ["All severities", "Severe", "High", "Moderate", "Low"];

    private string _detectionSeverityFilter = "All severities";

    public string DetectionSeverityFilter
    {
        get => _detectionSeverityFilter;
        set
        {
            if (Set(ref _detectionSeverityFilter, string.IsNullOrWhiteSpace(value) ? "All severities" : value))
            {
                ApplyDetectionFilter();
            }
        }
    }

    private string _detectionSearch = string.Empty;

    public string DetectionSearch
    {
        get => _detectionSearch;
        set
        {
            if (Set(ref _detectionSearch, value ?? string.Empty))
            {
                ApplyDetectionFilter();
            }
        }
    }

    public ObservableCollection<ThreatDetectionRow> FilteredDetections { get; } = [];

    public void ApplyDetectionFilter()
    {
        FilteredDetections.Clear();
        foreach (var row in Detections.Where(MatchesDetectionFilter))
        {
            FilteredDetections.Add(row);
        }

        if (SelectedDetection is not null && !FilteredDetections.Contains(SelectedDetection))
        {
            SelectedDetection = null;
            DetectionEvidence = null;
        }
    }

    private bool MatchesDetectionFilter(ThreatDetectionRow row)
    {
        if (!string.Equals(DetectionSeverityFilter, "All severities", StringComparison.Ordinal)
            && !string.Equals(row.Severity, DetectionSeverityFilter, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (DetectionSearch.Length > 0
            && !row.Threat.Contains(DetectionSearch, StringComparison.OrdinalIgnoreCase)
            && !row.Path.Contains(DetectionSearch, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return true;
    }

    public ObservableCollection<ThreatProcessRow> Processes { get; } = [];

    public ObservableCollection<PersistenceRow> Persistence { get; } = [];

    public ObservableCollection<QuarantineRow> Quarantine { get; } = [];

    // P21: the live watch feed. Deliberately OUTSIDE the Collect/
    // Apply channel: cards stream in while the app is open and a
    // page refresh must never wipe them. Newest first, capped.
    public const int MaxWatchFeed = 100;

    public ObservableCollection<WatchCardRow> WatchFeed { get; } = [];

    private string _watchLine = "Watch: starting…";

    public string WatchLine
    {
        get => _watchLine;
        private set => Set(ref _watchLine, value);
    }

    public void AddWatchCard(WatchCard card)
    {
        string detail = card.Detail;
        if (card.CoalescedCount > 0)
        {
            detail += $" (+{card.CoalescedCount} similar seen)";
        }

        WatchFeed.Insert(0, new WatchCardRow(
            card.ObservedUtc.ToLocalTime().ToString("HH:mm:ss"),
            card.Pid > 0 ? $"{card.Name} (PID {card.Pid})" : card.Name,
            card.Verdict,
            detail,
            card.Source == WatchSource.Process ? "process" : "file"));
        while (WatchFeed.Count > MaxWatchFeed)
        {
            WatchFeed.RemoveAt(WatchFeed.Count - 1);
        }
    }

    public void SetWatchLine(string line) => WatchLine = line;

    public void ClearWatchFeed()
    {
        WatchFeed.Clear();
        WatchLine = "Watch: starting…";
    }

    private string _banner = "Not inspected yet.";

    public string Banner
    {
        get => _banner;
        private set => Set(ref _banner, value);
    }

    private string _bannerDetail = string.Empty;

    public string BannerDetail
    {
        get => _bannerDetail;
        private set => Set(ref _bannerDetail, value);
    }

    private string _rtpState = "Unknown";

    // On | Off | Unknown — drives banner styling.
    public string RtpState
    {
        get => _rtpState;
        private set => Set(ref _rtpState, value);
    }

    private string _definitionsLine = "Unknown";

    public string DefinitionsLine
    {
        get => _definitionsLine;
        private set => Set(ref _definitionsLine, value);
    }

    private string _defenderScanLine = "Unknown";

    public string DefenderScanLine
    {
        get => _defenderScanLine;
        private set => Set(ref _defenderScanLine, value);
    }

    private string _coverage = string.Empty;

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

    private ThreatDetectionRow? _selectedDetection;

    public ThreatDetectionRow? SelectedDetection
    {
        get => _selectedDetection;
        set => Set(ref _selectedDetection, value);
    }

    private DetectionEvidence? _detectionEvidence;

    public DetectionEvidence? DetectionEvidence
    {
        get => _detectionEvidence;
        private set => Set(ref _detectionEvidence, value);
    }

    private ThreatProcessRow? _selectedProcess;

    public ThreatProcessRow? SelectedProcess
    {
        get => _selectedProcess;
        set => Set(ref _selectedProcess, value);
    }

    private string? _processDetailLine;

    public string? ProcessDetailLine
    {
        get => _processDetailLine;
        private set => Set(ref _processDetailLine, value);
    }

    private PersistenceRow? _selectedPersistence;

    public PersistenceRow? SelectedPersistence
    {
        get => _selectedPersistence;
        set => Set(ref _selectedPersistence, value);
    }

    private string? _persistenceDetailLine;

    public string? PersistenceDetailLine
    {
        get => _persistenceDetailLine;
        private set => Set(ref _persistenceDetailLine, value);
    }

    private QuarantineRow? _selectedQuarantine;

    public QuarantineRow? SelectedQuarantine
    {
        get => _selectedQuarantine;
        set => Set(ref _selectedQuarantine, value);
    }

    private string _quarantineNote = string.Empty;

    public string QuarantineNote
    {
        get => _quarantineNote;
        private set => Set(ref _quarantineNote, value);
    }

    private string _quarantineActionNote = string.Empty;

    public string QuarantineActionNote
    {
        get => _quarantineActionNote;
        private set => Set(ref _quarantineActionNote, value);
    }

    private FileCheckResult? _fileCheck;

    public FileCheckResult? FileCheck
    {
        get => _fileCheck;
        private set => Set(ref _fileCheck, value);
    }

    private string _scanNote = string.Empty;

    public string ScanNote
    {
        get => _scanNote;
        private set => Set(ref _scanNote, value);
    }

    private string _runKeyLine = "Run key · —";

    public string RunKeyLine
    {
        get => _runKeyLine;
        private set => Set(ref _runKeyLine, value);
    }

    private string _startupFolderLine = "Startup folder · —";

    public string StartupFolderLine
    {
        get => _startupFolderLine;
        private set => Set(ref _startupFolderLine, value);
    }

    private string _serviceLine = "Auto service · —";

    public string ServiceLine
    {
        get => _serviceLine;
        private set => Set(ref _serviceLine, value);
    }

    private string _taskLine = "Scheduled task · —";

    public string TaskLine
    {
        get => _taskLine;
        private set => Set(ref _taskLine, value);
    }

    private string _extensionLine = "Browser extension · —";

    public string ExtensionLine
    {
        get => _extensionLine;
        private set => Set(ref _extensionLine, value);
    }

    private string _wmiLine = "WMI subscription · —";

    public string WmiLine
    {
        get => _wmiLine;
        private set => Set(ref _wmiLine, value);
    }

    public void Refresh() => Apply(Collect());

    public static ThreatsSnapshot Collect()
    {
        var status = DefenderCollector.CollectStatus();
        var detections = DefenderCollector.CollectDetections(50);
        var processes = ProcessCollector.Collect();
        var runKeys = StartupCollector.CollectRunKeys();
        var folders = StartupCollector.CollectStartupFolders();
        var services = StartupCollector.CollectServices();
        // T51: persistence map + topography (all bounded, read-only).
        var tasks = ScheduledTaskCollector.Collect();
        var extensions = BrowserExtensionCollector.Collect();
        var wmi = WmiPersistenceCollector.Collect();

        string banner;
        string bannerDetail;
        string rtp;
        var row = status.Records.FirstOrDefault();
        if (row is null)
        {
            banner = "Microsoft Defender · status unavailable";
            bannerDetail = "Defender status could not be read — it may be managed by another app.";
            rtp = "Unknown";
        }
        else if (row.RealTimeProtectionEnabled == true)
        {
            banner = "Microsoft Defender · Real-time protection on";
            bannerDetail = "Your device is actively protected and monitored for threats.";
            rtp = "On";
        }
        else
        {
            banner = "Microsoft Defender · Real-time protection off";
            bannerDetail = "Real-time protection is off — turn it on in Windows Security.";
            rtp = "Off";
        }

        string definitions = row?.SignatureAgeDays is null
            ? "Unknown"
            : row.SignatureAgeDays is not int days ? "Date unknown"
            : days == 0 ? "Today" : $"{CountText.Of(days, "day")} ago";
        DateTime? lastScan = row?.LastQuickScanUtc ?? row?.LastFullScanUtc;
        if (row?.LastQuickScanUtc is not null && row?.LastFullScanUtc is not null)
        {
            lastScan = row.LastQuickScanUtc > row.LastFullScanUtc
                ? row.LastQuickScanUtc : row.LastFullScanUtc;
        }

        string defenderScan = lastScan is null
            ? "Never"
            : lastScan.Value.Date == DateTime.UtcNow.Date
                ? "Today, " + lastScan.Value.ToLocalTime().ToString("HH:mm")
                : lastScan.Value.ToLocalTime().ToString("d MMM yyyy, HH:mm");

        var detectionRows = detections.Records
            .OrderByDescending(d => d.DetectedUtc)
            .Select(d => new ThreatDetectionRow(
                d.ThreatName, d.Severity, d.Path ?? "—",
                d.DetectedUtc?.ToLocalTime().ToString("g") ?? "—",
                d.PendingAction ? "Pending" : (d.ActionTaken ?? "Recorded"),
                d.ThreatName.Contains("EICAR", StringComparison.OrdinalIgnoreCase)))
            .ToList();

        var processRows = processes.Records
            .OrderBy(p => string.IsNullOrWhiteSpace(p.Company) ? 0 : 1)
            .ThenByDescending(p => p.WorkingSetBytes)
            .Take(100)
            .Select(p => new ThreatProcessRow(
                $"{p.Name} (PID {p.Id})", p.Path ?? "—",
                string.IsNullOrWhiteSpace(p.Company) ? "Unknown company — check first" : p.Company,
                $"{p.WorkingSetBytes / 1024.0 / 1024.0:F0} MB",
                p.ParentId is null ? "Unknown parent"
                    : $"{p.ParentName ?? "exited process"} (PID {p.ParentId})",
                p.Id))
            .ToList();

        var runKeyRows = runKeys.Records
            .Select(r => new PersistenceRow("Run key", r.Name, r.Location)).ToList();
        var folderRows = folders.Records
            .Select(r => new PersistenceRow("Startup folder", r.Name, r.Command)).ToList();
        var serviceRows = services.Records
            .Where(s => s.StartType.Contains("Auto", StringComparison.OrdinalIgnoreCase))
            .Select(s => new PersistenceRow("Auto service", s.DisplayName, s.Status)).ToList();
        // T51: the rest of the persistence map (bounded collectors;
        // per-row suspicion carries a rule id, never a verdict).
        var taskRows = tasks.Records
            .Select(t => new PersistenceRow("Scheduled task", t.TaskName,
                $"{t.Status ?? "status unknown"}" +
                (t.NextRunTime is null ? string.Empty : $" · next {t.NextRunTime}")))
            .ToList();
        var extensionRows = extensions.Records
            .Select(e => new PersistenceRow("Browser extension",
                $"{e.Name} {e.Version}".Trim(),
                $"{e.Browser} · {e.Profile}",
                e.HasContentScripts
                    ? SuspicionExtensionContent
                    : string.Empty))
            .ToList();
        var wmiFilterRows = wmi.Records
            .SelectMany(w => w.Filters)
            .Select(f => new PersistenceRow("WMI filter", f.Name,
                f.Query is null ? "no query text" : Truncate(f.Query, 120),
                SuspicionWmiBinding))
            .ToList();
        var wmiBindingRows = wmi.Records
            .SelectMany(w => w.Bindings)
            .Select(b => new PersistenceRow("WMI binding", b.Filter, b.Consumer,
                SuspicionWmiBinding))
            .ToList();
        var persistenceRows = runKeyRows
            .Concat(folderRows).Concat(serviceRows)
            .Concat(taskRows).Concat(extensionRows)
            .Concat(wmiFilterRows).Concat(wmiBindingRows)
            .OrderBy(r => r.Type).ThenBy(r => r.Name)
            .Take(500)
            .ToList();

        // T52: CURRENT quarantine (live list, never history) with
        // detection-history correlation as explanation only.
        var quarantine = QuarantineCollector.Collect();
        var quarantineRows = quarantine.Records
            .Select(q => new QuarantineRow(
                q.Name,
                q.Threat ?? q.Name,
                q.Path ?? "location not listed",
                q.Detected ?? "date not listed",
                ExplainQuarantine(q, detections.Records)))
            .ToList();
        string quarantineNote = quarantine.Status switch
        {
            CollectionStatus.Failed when quarantine.Gaps.Any(
                g => g.Reason == "ElevationRequired") =>
                "The quarantine list needs administrator rights — it was not read. " +
                "Nothing is inferred from past detections.",
            CollectionStatus.Failed =>
                "The quarantine list could not be read — nothing is inferred from past detections.",
            _ when quarantineRows.Count == 0 =>
                "Quarantine is empty — Defender currently holds nothing.",
            _ => string.Empty,
        };

        var problems = new List<string>();
        void NoteTruncated<T>(string label, CollectionResult<T> r)
        {
            if (r is { Status: CollectionStatus.Success, Truncated: true })
            {
                problems.Add($"showing first {r.Records.Count} {label}");
            }
        }
        void NoteBound<T>(string label, CollectionResult<T> r)
        {
            foreach (var gap in r.Gaps)
            {
                problems.Add($"{label}: {gap.Reason}");
            }
        }
        void Note<T>(string label, CollectionResult<T> r)
        {
            if (r.Status != CollectionStatus.Success)
            {
                problems.Add($"{label}: {r.Status}");
            }
        }

        Note("Defender status", status);
        Note("Detections", detections);
        Note("Processes", processes);
        Note("Run keys", runKeys);
        Note("Startup folders", folders);
        Note("Services", services);
        Note("Scheduled tasks", tasks);
        Note("Browser extensions", extensions);
        Note("WMI subscriptions", wmi);
        Note("Quarantine", quarantine);
        NoteTruncated("tasks", tasks);
        NoteTruncated("extension profiles", extensions);
        NoteTruncated("quarantine entries", quarantine);
        NoteBound("WMI", wmi);

        return new ThreatsSnapshot(
            banner, bannerDetail, rtp, definitions, defenderScan,
            problems.Count == 0 ? "All sources inspected." : "Coverage: " + string.Join("; ", problems),
            detectionRows, processRows, persistenceRows,
            runKeyRows.Count, folderRows.Count, serviceRows.Count,
            "The persistence map lists every launch point read — nothing here is removed.",
            tasks.Records.Count, extensions.Records.Count,
            wmi.Records.SelectMany(w => w.Filters).Count() +
                wmi.Records.SelectMany(w => w.Bindings).Count(),
            quarantineRows, quarantineNote);
    }

    public void Apply(ThreatsSnapshot s)
    {
        // A09: a replaced page invalidates in-flight detail
        // reads along with the selection (page-collect tokens
        // were already consumed by the caller holding them).
        _evidenceGate.Next();
        _fileCheckGate.Next();
        _processGate.Next();
        _persistenceGate.Next();
        Banner = s.Banner;
        BannerDetail = s.BannerDetail;
        RtpState = s.RtpState;
        DefinitionsLine = s.Definitions;
        DefenderScanLine = s.DefenderScan;
        MachineLine = BuildMachineLine();
        Coverage = s.Coverage + " " + s.PersistenceNote;
        Detections.Clear();
        foreach (var row in s.Detections)
        {
            Detections.Add(row);
        }

        ApplyDetectionFilter();

        Processes.Clear();
        foreach (var row in s.Processes)
        {
            Processes.Add(row);
        }

        Persistence.Clear();
        foreach (var row in s.Persistence)
        {
            Persistence.Add(row);
        }

        Quarantine.Clear();
        if (s.QuarantineItems is not null)
        {
            foreach (var row in s.QuarantineItems)
            {
                Quarantine.Add(row);
            }
        }

        QuarantineNote = s.QuarantineNote;

        RunKeyLine = $"Run key · {Plural(s.RunKeyCount, "item")}";
        StartupFolderLine = $"Startup folder · {Plural(s.FolderCount, "item")}";
        ServiceLine = $"Auto service · {Plural(s.ServiceCount, "item")}";
        TaskLine = $"Scheduled task · {Plural(s.TaskCount, "item")}";
        ExtensionLine = $"Browser extension · {Plural(s.ExtensionCount, "item")}";
        WmiLine = $"WMI subscription · {Plural(s.WmiCount, "item")}";
        SelectedDetection = null;
        DetectionEvidence = null;
        SelectedProcess = null;
        ProcessDetailLine = null;
        SelectedPersistence = null;
        PersistenceDetailLine = null;
        SelectedQuarantine = null;
        QuarantineActionNote = string.Empty;
        ScanNote = string.Empty;
        RefreshState.NoteSuccess();
    }

    private static string Plural(int count, string noun)
    {
        return count == 1 ? $"1 {noun}" : $"{count} {noun}s";
    }

    private static string Truncate(string value, int max)
    {
        return value.Length <= max ? value : value[..max] + "…";
    }

    // T52: explains a CURRENTLY LISTED row from detection
    // history (severity/when/action). A listed row with no
    // matching detection says so — history rolling over never
    // un-lists it, and history alone never lists anything.
    internal static string ExplainQuarantine(
        QuarantineRecord row, IReadOnlyList<DefenderDetectionRecord> history)
    {
        var match = history.FirstOrDefault(d =>
            string.Equals(d.ThreatName, row.Threat ?? row.Name, StringComparison.OrdinalIgnoreCase));
        if (match is null)
        {
            return "Listed in current quarantine; no matching detection record — " +
                "the detection history may have rolled over. The listing is what counts.";
        }

        string when = match.DetectedUtc?.ToLocalTime().ToString("g") ?? "on an unrecorded date";
        string action = string.IsNullOrWhiteSpace(match.ActionTaken)
            ? "Defender holds it in quarantine."
            : $"Defender action on record: {match.ActionTaken}.";
        return $"Defender detected '{match.ThreatName}' ({match.Severity}) {when}. {action}";
    }

    // A09: attaches ONLY to the selection that requested it.
    // The view passes the token it took when the read started;
    // a token from before a refresh, or a path that no longer
    // matches the selection, is stale and dropped — an old hash
    // never lands on a new row (not even as a failure line).
    public void SetDetectionEvidence(long token, StaticFileEvidenceRecord? record, string path)
    {
        if (!_evidenceGate.IsCurrent(token) || SelectedDetection?.Path != path)
        {
            return;
        }

        if (record is null)
        {
            DetectionEvidence = new DetectionEvidence(
                "Not computed", "Signature unknown",
                "Evidence read failed — the file may need elevation.");
            return;
        }

        DetectionEvidence = new DetectionEvidence(
            record.Sha256 ?? "Not computed",
            !record.Exists ? "File not present"
                : record.Signed ? $"Signed · {record.SignerSubject ?? "unknown subject"}"
                : "Unsigned",
            record.Exists
                ? "Present on disk"
                : "Not present at its path (quarantined, removed, or moved).");
    }

    // T51: process detail = signer of the executable + live
    // connection join for its PID. Same staleness rule as
    // detection evidence (A09).
    public void SetProcessDetail(
        long token, int pid, StaticFileEvidenceRecord? record,
        IReadOnlyList<TcpConnectionRecord> connections)
    {
        if (!_processGate.IsCurrent(token) || SelectedProcess?.Id != pid)
        {
            return;
        }

        string signer = record switch
        {
            null => "Signature unknown",
            { Exists: false } => "Executable not present (exited or moved)",
            { Signed: true } => $"Signed · {record.SignerSubject ?? "unknown subject"}",
            _ => "Unsigned — treat with care.",
        };
        string network = connections.Count == 0
            ? "No network connections observed."
            : $"Connections: {connections.Count} (" +
              string.Join(", ", connections.Take(5).Select(c => c.Remote)) +
              (connections.Count > 5 ? ", …" : string.Empty) + ")";
        ProcessDetailLine = $"{signer} · {network}";
    }

    // T51: scheduled-task XML detail is read on demand (one
    // schtasks call per selection, never at scan time).
    public void SetPersistenceDetail(
        long token, PersistenceRow row, ScheduledTaskDetail? detail, string? note)
    {
        if (!_persistenceGate.IsCurrent(token) || SelectedPersistence != row)
        {
            return;
        }

        if (detail is null)
        {
            PersistenceDetailLine = note is null
                ? "Detail read failed — the task may need elevation."
                : note;
            return;
        }

        string hidden = detail.Hidden
            ? " · " + SuspicionTaskHidden
            : string.Empty;
        PersistenceDetailLine =
            $"Runs: {detail.Actions.FirstOrDefault() ?? "no action listed"} · " +
            $"Triggers: {detail.Triggers.FirstOrDefault() ?? "no trigger listed"}" +
            hidden;
    }

    // T51: non-task rows echo their observed detail plus any
    // check-first note — no further read is available.
    public void ShowPersistenceSummary(PersistenceRow row)
    {
        _persistenceGate.Next();
        PersistenceDetailLine = string.IsNullOrWhiteSpace(row.Suspicion)
            ? row.Detail
            : $"{row.Detail} · {row.Suspicion}";
    }

    // A09: same staleness rule for check-a-file: only the
    // newest request's completion attaches (rapid drops/checks
    // of different files can't reorder on screen).
    public void SetFileCheck(long token, StaticFileEvidenceRecord? record, string path, string? error)
    {
        if (!_fileCheckGate.IsCurrent(token))
        {
            return;
        }

        if (record is null)
        {
            FileCheck = new FileCheckResult(
                SafeFileName(path),
                "Not computed", "Signature unknown",
                error ?? "Evidence read failed.",
                error ?? "Evidence read failed — the file may need elevation.",
                UnavailableReputationAdapter.UnavailableDetail);
            return;
        }

        FileCheck = new FileCheckResult(
            SafeFileName(path),
            record.Sha256 ?? "Not computed",
            !record.Exists ? "File not present"
                : record.Signed ? $"Signed · {record.SignerSubject ?? "unknown subject"}"
                : "Unsigned — treat with care",
            record.LengthBytes is null ? "Size unknown" : $"{record.LengthBytes} bytes",
            ExplainFileEvidence(record),
            UnavailableReputationAdapter.UnavailableDetail);
    }

    // T53: grounded explanation of LOCAL static evidence only.
    // Every sentence traces to a record field; nothing here
    // executes the file, and unsigned is never called safe
    // (nor is signed called harmless — signatures prove origin,
    // not intent).
    internal static string ExplainFileEvidence(StaticFileEvidenceRecord record)
    {
        if (!record.Exists)
        {
            return "This file is not present at that path — nothing could be inspected.";
        }

        string origin = record.Signed
            ? $"Verified signature from {record.SignerSubject ?? record.SignerIssuer ?? "a known publisher"}: " +
              "a publisher signed this file. Signatures prove origin, not intent — " +
              "signed files can still be unwanted."
            : "No verified signature — treat with care. Unsigned includes every freshly " +
              "built program, so this alone means nothing bad.";
        string hash = record.Sha256 is null
            ? " Its hash could not be computed."
            : " Its SHA-256 fingerprint was recorded locally and sent nowhere.";
        return origin + hash;
    }

    public void NoteScan(string note)
    {
        ScanNote = note;
    }

    // T50: plan first (side-effect free); a Ready plan opens the
    // scan sheet, anything else stays a note. Code-behind calls
    // this for every scan button.
    public void BeginScan(DefenderScanRequest request)
    {
        var plan = DefenderScan.Plan(request);
        if (!plan.Ready)
        {
            NoteScan(plan.Detail);
            return;
        }

        if (_actions is null)
        {
            NoteScan(plan.Detail + " Confirmation is unavailable in this build — nothing was started.");
            return;
        }

        var template = ActionRegistry.Find("defender_scan");
        if (template is null || template.Status != TemplateStatus.Active)
        {
            NoteScan("Defender scans are unavailable in this build — nothing was started.");
            return;
        }

        NoteScan(plan.Detail);
        var sheet = new DefenderScanSheetViewModel(request, plan, template, _actions.Dispatcher)
        {
            ViewHistory = _actions.ViewHistory,
        };
        _actions.Host.Show(sheet);
    }

    // T52: typed restore for the selected CURRENT row (plan →
    // sheet-or-note, same containment as scans).
    public void BeginRestore(QuarantineRow row)
    {
        var plan = QuarantineRestore.Plan(new QuarantineRestoreRequest(row.Name));
        if (!plan.Ready)
        {
            NoteQuarantineAction(plan.Detail);
            return;
        }

        if (_actions?.QuarantineHost is null)
        {
            NoteQuarantineAction(
                plan.Detail + " Restore confirmation is unavailable in this build — nothing was started.");
            return;
        }

        var template = ActionRegistry.Find("quarantine_restore");
        if (template is null || template.Status != TemplateStatus.Active)
        {
            NoteQuarantineAction("Quarantine restore is unavailable in this build — nothing was started.");
            return;
        }

        NoteQuarantineAction(plan.Detail);
        var sheet = new QuarantineSheetViewModel(
            plan, row.Explanation, template, _actions.Dispatcher)
        {
            ViewHistory = _actions.ViewHistory,
        };
        _actions.QuarantineHost.Show(sheet);
    }

    // T52: Keep = an explicit no-op (the item stays quarantined;
    // nothing happens, so nothing is audited).
    public void NoteKeep(QuarantineRow row) =>
        NoteQuarantineAction($"'{row.Name}' stays in quarantine — nothing changed.");

    // T52: Report = Defender's own submission page (the user acts
    // in the browser; Sentinel uploads nothing itself).
    public void ReportQuarantine(QuarantineRow row)
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = MicrosoftSubmissionUrl,
                UseShellExecute = true,
            });
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // Stay silent like the driver link-outs: the note
            // below still tells the user where to go.
        }

        NoteQuarantineAction(
            $"'{row.Name}': opened Microsoft's sample-submission page — " +
            "anything sent there is your own upload, not Sentinel's.");
    }

    internal const string MicrosoftSubmissionUrl =
        "https://www.microsoft.com/en-us/wdsi/filesubmission";

    public void NoteQuarantineAction(string note) => QuarantineActionNote = note;

    internal static string SafeFileName(string path)
    {
        try
        {
            string name = Path.GetFileName(path);
            return string.IsNullOrEmpty(name) ? path : name;
        }
        catch
        {
            return path;
        }
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

    public sealed record ThreatsSnapshot(
        string Banner,
        string BannerDetail,
        string RtpState,
        string Definitions,
        string DefenderScan,
        string Coverage,
        IReadOnlyList<ThreatDetectionRow> Detections,
        IReadOnlyList<ThreatProcessRow> Processes,
        IReadOnlyList<PersistenceRow> Persistence,
        int RunKeyCount,
        int FolderCount,
        int ServiceCount,
        string PersistenceNote,
        int TaskCount = 0,
        int ExtensionCount = 0,
        int WmiCount = 0,
        IReadOnlyList<QuarantineRow>? QuarantineItems = null,
        string QuarantineNote = "");
}
