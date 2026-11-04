// P1-06b board 08 (Reports): technician report with library, zoomable preview,
// and HTML/JSON export. All sections come from live read-only collectors plus
// the scan database; "Not in this report" is always shown. Previous-report
// history stays an honest empty state (no persistence backend).
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.Win32;
using Sentinel.App.Services;
using Sentinel.Engine.CrashDoctor;
using Sentinel.Engine.Scan;
using Sentinel.Engine.SystemInventory;
using Sentinel.Store;

namespace Sentinel.App.ViewModels;

// T55: one open-issue row with a user include-toggle. Fires
// Toggled (the page re-issues the draft); the row itself owns
// no report logic.
public sealed class SelectableFinding : ViewModelBase
{
    public SelectableFinding(string issue, bool included)
    {
        Issue = issue;
        _included = included;
    }

    public event Action? Toggled;

    public string Issue { get; }

    private bool _included;

    public bool Included
    {
        get => _included;
        set
        {
            if (Set(ref _included, value))
            {
                Toggled?.Invoke();
            }
        }
    }
}

public sealed class ReportsViewModel : ViewModelBase
{
    // A09: versions GenerateAsync builds; faults surface here
    // with the last draft kept.
    public RefreshTracker RefreshState { get; } = new();

    private readonly Func<SentinelDb> _dbFactory;
    private readonly Func<ActionAuditLog>? _auditFactory;
    private readonly ReportLibrary _library;

    public ReportsViewModel(
        Func<SentinelDb> dbFactory,
        Func<ActionAuditLog>? auditFactory = null,
        ReportLibrary? library = null)
    {
        _dbFactory = dbFactory;
        _auditFactory = auditFactory;
        _library = library ?? new ReportLibrary(SentinelPaths.ReportsDirectory);
        CopyPreviewCommand = new RelayCommand(
            _ => CopyText(Preview),
            _ => HasDraft);
        ReviewFindingsCommand = new RelayCommand(_ => NavigateToPage?.Invoke(2));
        SaveDraftCommand = new RelayCommand(_ => SaveDraft(), _ => HasDraft);
        ReopenCommand = new RelayCommand(
            _ => ReopenSelected(),
            _ => SelectedSaved is not null);
        RefreshLibrary();
    }

    private string _preview = "Press Generate to build the technician report from live data.";

    public string Preview
    {
        get => _preview;
        private set => Set(ref _preview, value);
    }

    public string NotInReport { get; } =
        "Not in this report: file contents, deleted files, passwords or keys, photos, or anything from outside this PC.";

    private string _reportHistory = string.Empty;

    public string ReportHistory
    {
        get => _reportHistory;
        private set => Set(ref _reportHistory, value);
    }

    private TechnicianReport? _report;

    public TechnicianReport? Draft
    {
        get => _report;
        private set
        {
            if (Set(ref _report, value))
            {
                Raise(nameof(HasDraft));
                Raise(nameof(DraftTitle));
            }
        }
    }

    public bool HasDraft => _report is not null;

    public string DraftTitle => _report is null
        ? "No draft yet"
        : $"This PC · {_report.GeneratedAt.ToLocalTime():d MMM yyyy}";

    private string _draftState = "Not yet generated";

    public string DraftState
    {
        get => _draftState;
        private set => Set(ref _draftState, value);
    }

    private string _exportFormat = "HTML";

    public string ExportFormat
    {
        get => _exportFormat;
        set
        {
            // T55: HTML and JSON are the only formats — anything
            // else (there is no PDF) is ignored, never half-honored.
            if (!value.Equals("HTML", StringComparison.OrdinalIgnoreCase)
                && !value.Equals("JSON", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            // U25: the preview IS the export bytes in the selected
            // format — changing format re-renders from the same
            // draft and the same builders.
            if (Set(ref _exportFormat, value) && Draft is not null)
            {
                Preview = RenderPreview();
            }
        }
    }

    private bool _isGenerating;

    public bool IsGenerating
    {
        get => _isGenerating;
        private set => Set(ref _isGenerating, value);
    }

    public Action<int>? NavigateToPage { get; set; }

    public ICommand CopyPreviewCommand { get; }

    public ICommand ReviewFindingsCommand { get; }

    public ICommand SaveDraftCommand { get; }

    public ICommand ReopenCommand { get; }

    public ObservableCollection<SelectableFinding> FindingSelections { get; } = [];

    public ObservableCollection<SavedReportEntry> SavedReports { get; } = [];

    private SavedReportEntry? _selectedSaved;

    public SavedReportEntry? SelectedSaved
    {
        get => _selectedSaved;
        set
        {
            if (Set(ref _selectedSaved, value))
            {
                ((RelayCommand)ReopenCommand).RaiseCanExecuteChanged();
            }
        }
    }

    private string _libraryNote = string.Empty;

    public string LibraryNote
    {
        get => _libraryNote;
        private set => Set(ref _libraryNote, value);
    }

    public void Generate() => Apply(Build());

    public void Apply(TechnicianReport r)
    {
        Draft = r;
        FindingSelections.Clear();
        foreach (string issue in r.OpenIssues)
        {
            var row = new SelectableFinding(issue, true);
            row.Toggled += ApplyFindingSelection;
            FindingSelections.Add(row);
        }

        Preview = RenderPreview();
        DraftState = "Not yet exported";
        RefreshState.NoteSuccess();
        ((RelayCommand)SaveDraftCommand).RaiseCanExecuteChanged();
    }

    // T55: user-selected findings — unchecking a finding
    // re-issues the draft without it (and counts the excluded).
    // The full list stays in the checkbox panel for re-adding.
    public void ApplyFindingSelection()
    {
        if (Draft is null)
        {
            return;
        }

        var included = FindingSelections.Where(f => f.Included).Select(f => f.Issue).ToList();
        int excluded = FindingSelections.Count - included.Count;
        Draft = Draft with { OpenIssues = included, ExcludedFindings = excluded };
        Preview = RenderPreview();
    }

    // T55: save / reopen / re-export. Saved files are JSON drafts
    // in the Reports directory — re-export renders the reopened
    // draft through the same builders (file share only: nothing
    // is uploaded anywhere).
    public void SaveDraft()
    {
        if (Draft is null)
        {
            return;
        }

        try
        {
            var entry = _library.Save(BuildReportJson());
            RefreshLibrary();
            SelectedSaved = SavedReports.FirstOrDefault(e => e.FileName == entry.FileName);
            LibraryNote = $"Saved {entry.FileName}.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            LibraryNote = "Save failed — the report file could not be written.";
        }
    }

    public void ReopenSelected()
    {
        if (SelectedSaved is null)
        {
            return;
        }

        string? json = _library.Load(SelectedSaved.FileName);
        if (json is null)
        {
            LibraryNote = $"Could not read {SelectedSaved.FileName} — the file is missing or not a report.";
            return;
        }

        TechnicianReport? reopened;
        try
        {
            reopened = JsonSerializer.Deserialize<TechnicianReport>(json);
        }
        catch (JsonException)
        {
            reopened = null;
        }

        if (reopened is null)
        {
            LibraryNote = $"Could not read {SelectedSaved.FileName} — it is not a report draft.";
            return;
        }

        Apply(reopened);
        DraftState = $"Reopened {SelectedSaved.FileName}";
        LibraryNote = string.Empty;
    }

    public void RefreshLibrary()
    {
        SavedReports.Clear();
        foreach (var entry in _library.List())
        {
            SavedReports.Add(entry);
        }

        ReportHistory = SavedReports.Count == 0
            ? "No saved reports yet — Generate one, then Save draft to keep it here."
            : $"{CountText.Of(SavedReports.Count, "saved report")} — select one to reopen it.";
    }

    // U25: preview and export share one model and one pair of
    // builders — what you see is byte-identical to what ships.
    private string RenderPreview()
    {
        return ExportFormat.Equals("JSON", StringComparison.OrdinalIgnoreCase)
            ? BuildReportJson()
            : BuildReportHtml();
    }

    // A09: routed through the versioned helper — a fault
    // records an observable error (last draft kept) instead
    // of crashing the awaiting click handler, and a superseded
    // build never Applies. Never throws.
    public Task GenerateAsync(Func<TechnicianReport>? build = null)
    {
        if (IsGenerating)
        {
            return Task.CompletedTask;
        }

        IsGenerating = true;
        return PageRefresh.Run(
            RefreshState, build ?? Build, Apply, "report",
            PageRefresh.CaptureUiOrDefault(),
            () => IsGenerating = false);
    }

    private static void CopyText(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return;
        }

        try
        {
            System.Windows.Clipboard.SetText(text);
        }
        catch (System.Runtime.InteropServices.ExternalException)
        {
            // Clipboard busy — the preview stays visible on screen.
        }
    }

    public string BuildReportJson()
    {
        Draft ??= Build();
        if (DraftState == "Not yet generated")
        {
            DraftState = "Not yet exported";
        }

        return JsonSerializer.Serialize(Draft, new JsonSerializerOptions { WriteIndented = true });
    }

    public string BuildReportHtml()
    {
        Draft ??= Build();
        if (DraftState == "Not yet generated")
        {
            DraftState = "Not yet exported";
        }

        var r = Draft;
        var html = new StringBuilder();
        html.Append("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Sentinel report</title>");
        html.Append("<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#111}");
        html.Append("table{border-collapse:collapse;margin:8px 0}th,td{border:1px solid #999;padding:4px 10px;text-align:left}");
        html.Append("h1{font-size:20px}h2{font-size:15px;margin-top:20px}</style></head><body>");
        html.Append("<h1>Sentinel technician report</h1>");
        html.Append("<p>").Append(Escape(r.GeneratedLocal)).Append(" — ").Append(Escape(r.Machine)).Append("</p>");
        html.Append("<h2>Device summary</h2><p>").Append(Escape(r.OsName)).Append("<br>Scope: ")
            .Append(Escape(r.ScanScope)).Append("<br>Coverage: ").Append(Escape(r.CoverageLine)).Append("</p>");
        html.Append("<h2>Storage</h2><p>").Append(Escape(r.Storage)).Append("</p><ul>");
        foreach (var drive in r.DriveLines)
        {
            html.Append("<li>").Append(Escape(drive)).Append("</li>");
        }

        html.Append("</ul><h2>Devices and drivers</h2><p>").Append(Escape(r.Drivers)).Append("</p><ul>");
        foreach (var issue in r.DriverIssueNames)
        {
            html.Append("<li>").Append(Escape(issue)).Append("</li>");
        }

        html.Append("</ul><h2>Stability</h2><p>").Append(Escape(r.StabilityDetail)).Append("</p>");
        html.Append("<h2>Protection</h2><p>").Append(Escape(r.ProtectionDetail)).Append("</p>");
        html.Append("<h2>Recent actions</h2><p>").Append(Escape(r.ActionsCoverage)).Append("</p><ul>");
        if (r.ActionLines.Count == 0)
        {
            html.Append("<li>No actions on record.</li>");
        }

        foreach (var line in r.ActionLines)
        {
            html.Append("<li>").Append(Escape(line)).Append("</li>");
        }

        html.Append("</ul><h2>Open questions</h2><ul>");
        if (r.OpenIssues.Count == 0)
        {
            html.Append("<li>None found in this inspection.</li>");
        }

        foreach (var issue in r.OpenIssues)
        {
            html.Append("<li>").Append(Escape(issue)).Append("</li>");
        }

        html.Append("</ul>");
        if (r.ExcludedFindings > 0)
        {
            html.Append("<p>").Append(Escape(
                $"{CountText.Of(r.ExcludedFindings, "finding")} excluded at your choice."))
                .Append("</p>");
        }

        html.Append("<h2>Photos</h2><p>").Append(Escape(r.PhotoNote)).Append("</p>");
        html.Append("<h2>Section coverage</h2><table><tr><th>Section</th><th>Scope</th><th>Observed</th><th>Coverage</th></tr>");
        foreach (var section in r.Sections)
        {
            html.Append("<tr><td>").Append(Escape(section.Section)).Append("</td><td>")
                .Append(Escape(section.Scope)).Append("</td><td>")
                .Append(Escape(section.At)).Append("</td><td>")
                .Append(Escape(section.Coverage)).Append("</td></tr>");
        }

        html.Append("</table><p><i>").Append(Escape(NotInReport)).Append("</i></p></body></html>");
        return html.ToString();
    }

    public bool WriteExport(string path)
    {
        try
        {
            string content = ExportFormat.Equals("JSON", StringComparison.OrdinalIgnoreCase)
                ? BuildReportJson()
                : BuildReportHtml();
            File.WriteAllText(path, content, Encoding.UTF8);
            DraftState = $"Exported {ExportFormat} · {DateTime.Now:t}";
            return true;
        }
        catch (IOException)
        {
            DraftState = "Export failed — the file could not be written.";
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            DraftState = "Export failed — access denied for that location.";
            return false;
        }
    }

    public static string ReadOsName()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            string? product = key?.GetValue("ProductName") as string;
            string? display = key?.GetValue("DisplayVersion") as string;
            if (!string.IsNullOrWhiteSpace(product))
            {
                return string.IsNullOrWhiteSpace(display) ? product : $"{product} {display}";
            }
        }
        catch (System.Security.SecurityException)
        {
            // Locked-down registry — fall through to the OS version string.
        }

        return Environment.OSVersion.ToString();
    }

    public static string GroupRepeatedWarnings(IEnumerable<TargetedEventRecord> records)
    {
        var groups = new Dictionary<string, int>(StringComparer.Ordinal);
        int total = 0;
        foreach (var record in records)
        {
            if (record.Id is not (55 or 153))
            {
                continue;
            }

            total++;
            var tokens = CrashExplainer.ParseDeviceTokens(record.Message ?? string.Empty);
            string key = tokens.Count > 0 ? tokens.First() : "(device not named)";
            groups[key] = groups.TryGetValue(key, out int count) ? count + 1 : 1;
        }

        if (total == 0)
        {
            return "None";
        }

        var top = groups.OrderByDescending(g => g.Value).First();
        return top.Value >= 2 ? $"{total} (same device: {top.Key})" : total.ToString(CultureInfo.CurrentCulture);
    }

    private TechnicianReport Build()
    {
        using var db = _dbFactory();
        long files = 0;
        long bytes = 0;
        IReadOnlyList<ScanRunInfo> runs = Array.Empty<ScanRunInfo>();
        try
        {
            files = db.CountFingerprints();
            bytes = db.SumFingerprintBytes();
            runs = db.ListRuns(200);
        }
        catch
        {
            // Degraded report section, stated below.
        }

        var latest = runs.FirstOrDefault(r =>
            r.Status.Equals("Completed", StringComparison.OrdinalIgnoreCase));
        string scope = latest is null
            ? "No scan on record — device snapshot only"
            : $"{latest.Root} · {latest.Mode} · {ParseUtc(latest.StartedUtc).ToLocalTime():d MMM yyyy}";
        string coverage = latest is null
            ? "No scan on record"
            : $"{CountText.Of(latest.FilesSeen, "file")} ({latest.GapsCount} uninspected)";
        // A07: the storage totals below span retained inventory,
        // while scope/coverage bind to the latest completed run.
        // With multi-scope history the line must say so.
        int scopeCount = ScanScopeLabels.CountDistinctRoots(runs);
        string storage = scopeCount > 1
            ? $"{CountText.Of(files, "file")} · {bytes / 1024.0 / 1024.0:F0} MB inventoried across {CountText.Of(scopeCount, "location")}"
            : $"{CountText.Of(files, "file")} · {bytes / 1024.0 / 1024.0:F0} MB inventoried";

        var driveLines = new List<string>();
        try
        {
            foreach (var drive in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed))
            {
                try
                {
                    if (!drive.IsReady)
                    {
                        driveLines.Add($"{drive.Name} — not ready");
                        continue;
                    }

                    double totalGb = drive.TotalSize / 1024.0 / 1024.0 / 1024.0;
                    double usedGb = (drive.TotalSize - drive.TotalFreeSpace) / 1024.0 / 1024.0 / 1024.0;
                    int pct = drive.TotalSize == 0 ? 0 : (int)(100.0 * usedGb / totalGb);
                    driveLines.Add($"{drive.Name} — {usedGb:F0} GB used of {totalGb:F0} GB ({pct}%)");
                }
                catch (IOException)
                {
                    driveLines.Add($"{drive.Name} — unreadable");
                }
                catch (UnauthorizedAccessException)
                {
                    driveLines.Add($"{drive.Name} — access denied");
                }
            }
        }
        catch
        {
            driveLines.Add("Drive list unreadable.");
        }

        int totalDevices = 0;
        IReadOnlyList<DriverProblemRow> problems = Array.Empty<DriverProblemRow>();
        string driverCoverage = "device state unreadable";
        try
        {
            var drivers = DriversViewModel.Collect();
            problems = drivers.Problems;
            totalDevices = DriversViewModel.BuildDevices(problems, drivers.Drivers, drivers.Coverage).Count;
            driverCoverage = drivers.Coverage;
        }
        catch
        {
            // Stated in the drivers line below.
        }

        var defender = DefenderCollector.CollectStatus();
        var detections = DefenderCollector.CollectDetections(10);
        var sysEvents = EventCollector.CollectTargeted("System", null, 2, DateTime.UtcNow.AddDays(-30), 200);
        int crashes = sysEvents.Records.Count(e => e.Id is 1001 or 41 or 6008 or 55 or 153);
        string repeated = GroupRepeatedWarnings(sysEvents.Records);

        var issues = new List<string>();
        if (runs.Count == 0)
        {
            issues.Add("No Storage scan on record — run one for itemized findings.");
        }
        else if (latest is not null && latest.GapsCount > 0)
        {
            issues.Add($"{CountText.Of(latest.GapsCount, "location")} couldn't be inspected — confirm external drives are expected.");
        }

        if (problems.Count > 0)
        {
            issues.Add($"{CountText.Of(problems.Count, "device problem")} — see Drivers page.");
        }

        var defenderRow = defender.Records.FirstOrDefault();
        if (defenderRow?.RealTimeProtectionEnabled != true)
        {
            issues.Add("Real-time protection is off or unreadable — see Threats page.");
        }

        if (defenderRow?.SignatureAgeDays is int age && age > 7)
        {
            issues.Add($"Defender signatures are {CountText.Of(age, "day")} old — see Threats page.");
        }

        if (detections.Records.Count > 0)
        {
            issues.Add($"{CountText.Of(detections.Records.Count, "Defender detection")} on record — see Threats page.");
        }

        if (crashes > 0)
        {
            issues.Add($"{CountText.Of(crashes, "crash event")} in 30 days — see Crashes page.");
        }

        if (repeated != "None")
        {
            issues.Add($"Repeated disk warnings ({repeated}) — see Crashes page.");
        }

        var issueNames = problems
            .Take(5)
            .Select(p => $"{p.Device} — {p.Problem}")
            .ToList();
        string protectionDetail = defenderRow is null
            ? "Defender status unreadable"
            : $"Real-time protection {(defenderRow.RealTimeProtectionEnabled == true ? "on" : "OFF")}" +
              (defenderRow.SignatureAgeDays is int sigAge ? $" · signatures {CountText.Of(sigAge, "day")} old" : string.Empty) +
              $" · {CountText.Of(detections.Records.Count, "detection")}";

        // T55: recent actions from the audit log (E34) — time,
        // template, actor, undo state. No finding contents, no
        // raw dumps: one line per entry, newest first, capped.
        var actionLines = new List<string>();
        string actionsCoverage;
        if (_auditFactory is null)
        {
            actionsCoverage = "audit log not connected in this build";
        }
        else
        {
            try
            {
                using var audit = _auditFactory();
                var recent = audit.ListRecent(10);
                foreach (var entry in recent)
                {
                    string when = DateTime.TryParse(entry.Utc, null,
                            DateTimeStyles.AdjustToUniversal, out var parsed)
                        ? parsed.ToLocalTime().ToString("g")
                        : entry.Utc;
                    actionLines.Add($"{when} · {entry.ActionId} · {entry.Actor} · undo: {entry.UndoState}");
                }

                actionsCoverage = recent.Count == 0
                    ? "audit log connected — no actions recorded yet"
                    : $"last {CountText.Of(recent.Count, "audit entry", "audit entries")} (newest first)";
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                actionsCoverage = "audit log unreadable";
            }
        }

        string generatedLocal = DateTime.Now.ToString("F");
        DateTime generatedAt = DateTime.Now;
        string observedAt = generatedAt.ToString("g");
        var sections = new List<SectionCoverage>
        {
            new("Device", "this PC", observedAt, "snapshot read at generation time"),
            new("Storage", scope, observedAt, coverage),
            new("Drivers", "device snapshot", observedAt, driverCoverage),
            new("Crashes", "System log, last 30 days", observedAt,
                sysEvents.Status == CollectionStatus.Success
                    ? $"{CountText.Of(sysEvents.Records.Count, "event")} read"
                    : $"event log {sysEvents.Status.ToString().ToLowerInvariant()}"),
            new("Threats", "Defender state + recent detections", observedAt,
                defender.Status == CollectionStatus.Success
                    ? $"{CountText.Of(detections.Records.Count, "detection")} on record"
                    : "Defender state unreadable"),
            new("Actions", "audit log", observedAt, actionsCoverage),
            new("Open issues", "derived from the sections above", observedAt,
                $"{CountText.Of(issues.Count, "finding")} listed"),
            new("Photos", "none attached", observedAt, "no photo diagnoses in this build"),
        };
        const string photoNote =
            "No photo diagnoses in this report — photo upload and analysis are not in this build, " +
            "so no images were sent anywhere.";

        return new TechnicianReport(
            generatedLocal,
            generatedAt,
            Environment.MachineName,
            ReadOsName(),
            KnowledgePack.PackVersion,
            scope,
            coverage,
            storage,
            driveLines,
            problems.Count == 0 && driverCoverage == "device state unreadable"
                ? "device state unreadable"
                : $"{CountText.Of(problems.Count, "problem")} across {CountText.Of(totalDevices, "device")}",
            totalDevices,
            issueNames,
            defenderRow is null
                ? "Defender status unreadable"
                : $"RTP {(defenderRow.RealTimeProtectionEnabled == true ? "on" : "OFF")} · {CountText.Of(detections.Records.Count, "detection")}",
            protectionDetail,
            detections.Records.Count,
            crashes.ToString(CultureInfo.CurrentCulture),
            $"{CountText.Of(crashes, "crash event")} · repeated disk warnings: {repeated}",
            repeated,
            runs.Count.ToString(CultureInfo.CurrentCulture),
            issues,
            sections,
            actionLines,
            actionsCoverage,
            photoNote,
            0);
    }

    private static DateTime ParseUtc(string text) =>
        DateTime.TryParse(text, null, DateTimeStyles.AdjustToUniversal, out var parsed)
            ? parsed.ToUniversalTime()
            : DateTime.MinValue;

    private static string Escape(string text) =>
        text.Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal);

    // T55: per-section scope/time/coverage — every section
    // states what was inspected, when, and how complete the
    // read was (never a bare list of findings).
    public sealed record SectionCoverage(
        string Section,
        string Scope,
        string At,
        string Coverage);

    public sealed record TechnicianReport(
        string GeneratedLocal,
        DateTime GeneratedAt,
        string Machine,
        string OsName,
        string PackVersion,
        string ScanScope,
        string CoverageLine,
        string Storage,
        IReadOnlyList<string> DriveLines,
        string Drivers,
        int TotalDevices,
        IReadOnlyList<string> DriverIssueNames,
        string Protection,
        string ProtectionDetail,
        int DetectionCount,
        string Crashes,
        string StabilityDetail,
        string RepeatedWarnings,
        string Scans,
        IReadOnlyList<string> OpenIssues,
        IReadOnlyList<SectionCoverage> Sections,
        IReadOnlyList<string> ActionLines,
        string ActionsCoverage,
        string PhotoNote,
        int ExcludedFindings);
}