// P1-06b board 06 (Crashes & hangs): timeline strip, filtered table, evidence drawer,
// weekly bars. Real anchors + cards only; no photo-diagnosis backend exists, so the
// board's planned-diagnose action is not shown.
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using Sentinel.App.Services;
using Sentinel.Engine.CrashDoctor;
using Sentinel.Engine.SystemInventory;
using Sentinel.Store;

namespace Sentinel.App.ViewModels;

public sealed class CrashesViewModel : ViewModelBase
{
    // A09: versions RefreshAsync collects; faults surface here
    // with the last rows kept.
    public RefreshTracker RefreshState { get; } = new();

    public sealed record CrashRow(
        string When,
        string Type,
        string Summary,
        int EventId,
        int Index,
        TargetedEventRecord Anchor);

    public sealed record WeekBucket(string Label, int Crash, int Hang, int Disk, int Update, int Hardware)
    {
        public int Total => Crash + Hang + Disk + Update + Hardware;
    }

    public const string TypeCrash = "Crash";
    public const string TypeHang = "Hang";
    public const string TypeDisk = "Disk warning";
    public const string TypeUpdate = "Update";
    public const string TypeHardware = "Hardware error";

    // P24: event ID 19 is ambiguous (Windows Update success vs
    // WHEA hardware error), so the WHEA provider claims its own
    // bucket. Non-WHEA 19s keep the Update mapping.
    public static string TypeFor(TargetedEventRecord record)
    {
        if (record.Provider.Contains("WHEA", StringComparison.OrdinalIgnoreCase))
        {
            return TypeHardware;
        }

        return record.Id switch
        {
            1002 => TypeHang,
            55 or 153 => TypeDisk,
            19 => TypeUpdate,
            _ => TypeCrash,
        };
    }

    public static IReadOnlyList<WeekBucket> BucketizeWeeks(IEnumerable<CrashRow> rows, DateTime utcNow)
    {
        var buckets = new int[5, 5];
        foreach (var row in rows)
        {
            int week = (int)(utcNow.Date - row.Anchor.TimeUtc.Date).TotalDays / 7;
            if (week < 0)
            {
                week = 0;
            }

            if (week > 4)
            {
                continue;
            }

            buckets[week, row.Type switch
            {
                TypeHang => 1,
                TypeDisk => 2,
                TypeUpdate => 3,
                TypeHardware => 4,
                _ => 0,
            }]++;
        }

        var result = new List<WeekBucket>(5);
        for (int week = 4; week >= 0; week--)
        {
            var start = utcNow.Date.AddDays(-7 * week);
            result.Add(new WeekBucket(
                start.ToString("M/d"),
                buckets[week, 0], buckets[week, 1], buckets[week, 2], buckets[week, 3],
                buckets[week, 4]));
        }

        return result;
    }

    private IReadOnlyList<CrashCard> _cards = Array.Empty<CrashCard>();

    public string MachineName { get; } = Environment.MachineName;

    public ObservableCollection<CrashRow> Timeline { get; } = new();

    public ObservableCollection<CrashRow> VisibleRows { get; } = new();

    private IReadOnlyList<CrashRow> _rangeRows = Array.Empty<CrashRow>();

    public IReadOnlyList<CrashRow> RangeRows
    {
        get => _rangeRows;
        private set => Set(ref _rangeRows, value);
    }

    private IReadOnlyList<WeekBucket> _weeks = Array.Empty<WeekBucket>();

    public IReadOnlyList<WeekBucket> Weeks
    {
        get => _weeks;
        private set => Set(ref _weeks, value);
    }

    public IReadOnlyList<string> RangeOptions { get; } =
        new[] { "Last 7 days", "Last 30 days" };

    public IReadOnlyList<string> TypeOptions { get; } =
        new[] { "All event types", TypeCrash, TypeHang, TypeDisk, TypeUpdate, TypeHardware };

    private string _selectedRange = "Last 30 days";

    public string SelectedRange
    {
        get => _selectedRange;
        set
        {
            if (Set(ref _selectedRange, value))
            {
                RefillVisible();
            }
        }
    }

    private string _selectedEventType = "All event types";

    public string SelectedEventType
    {
        get => _selectedEventType;
        set
        {
            if (Set(ref _selectedEventType, value))
            {
                RefillVisible();
            }
        }
    }

    private int _relatedEventId = -1;

    public int RelatedEventId
    {
        get => _relatedEventId;
        set
        {
            if (Set(ref _relatedEventId, value))
            {
                Raise(nameof(RelatedCaption));
                Raise(nameof(HasRelatedFilter));
                RefillVisible();
            }
        }
    }

    public string RelatedCaption => RelatedEventId < 0
        ? string.Empty
        : $"Showing only Event {RelatedEventId}";

    public bool HasRelatedFilter => RelatedEventId >= 0;

    public string SelectedDevice
    {
        get
        {
            if (SelectedAnchor is null)
            {
                return string.Empty;
            }

            var tokens = CrashExplainer.ParseDeviceTokens(SelectedAnchor.Message ?? string.Empty);
            return tokens.Count > 0
                ? string.Join(", ", tokens.Take(2))
                : "Not named in the event";
        }
    }

    public int CrashCount => RangeRows.Count(r => r.Type == TypeCrash);

    public int HangCount => RangeRows.Count(r => r.Type == TypeHang);

    public int DiskCount => RangeRows.Count(r => r.Type == TypeDisk);

    public int UpdateCount => RangeRows.Count(r => r.Type == TypeUpdate);

    public int HardwareCount => RangeRows.Count(r => r.Type == TypeHardware);

    private CrashRow? _selectedRow;

    public CrashRow? SelectedRow
    {
        get => _selectedRow;
        set
        {
            if (Set(ref _selectedRow, value))
            {
                Raise(nameof(SelectedCard));
                Raise(nameof(SelectedAnchor));
                Raise(nameof(HasSelection));
                Raise(nameof(OverallConfidence));
                Raise(nameof(SelectedDevice));
                Raise(nameof(DetailBody));
            }
        }
    }

    public bool HasSelection => SelectedRow is not null;

    private string _deepLinkNote = string.Empty;

    // U21: scope carried by an Overview deep link ("From Overview:
    // DISK 2"). Sticky until the next deep link — a page refresh
    // does not invalidate where you came from.
    public string DeepLinkNote
    {
        get => _deepLinkNote;
        set
        {
            if (Set(ref _deepLinkNote, value ?? string.Empty))
            {
                Raise(nameof(HasDeepLinkNote));
            }
        }
    }

    public bool HasDeepLinkNote => DeepLinkNote.Length > 0;

    // U27: Ask-driven highlight. Raised after selecting the row so
    // the view can scroll it into view.
    public event Action<CrashRow>? HighlightRequested;

    // U27: selects the visible row whose card title matches the Ask
    // row key. Unknown keys keep the current selection (never a
    // blind jump).
    public void HighlightRow(string? title)
    {
        if (string.IsNullOrEmpty(title))
        {
            return;
        }

        var match = VisibleRows.FirstOrDefault(r =>
            r.Index >= 0 && r.Index < _cards.Count
            && string.Equals(_cards[r.Index].Title, title, StringComparison.Ordinal));
        if (match is null)
        {
            return;
        }

        SelectedRow = match;
        SelectedIndex = VisibleRows.IndexOf(match);
        HighlightRequested?.Invoke(match);
    }

    public CrashCard? SelectedCard => SelectedRow is null
        ? null
        : SelectedRow.Index >= 0 && SelectedRow.Index < _cards.Count
            ? _cards[SelectedRow.Index]
            : null;

    public TargetedEventRecord? SelectedAnchor => SelectedRow?.Anchor;

    public string OverallConfidence => SelectedCard is null
        ? string.Empty
        : SelectedCard.Findings.Count > 0
            ? SelectedCard.Findings[0].Confidence.ToString()
            : "No knowledge-pack match";

    private int _selectedIndex = -1;

    // Position of the selection inside VisibleRows (kept for the test contract).
    public int SelectedIndex
    {
        get => _selectedIndex;
        set
        {
            if (Set(ref _selectedIndex, value))
            {
                SelectedRow = value >= 0 && value < VisibleRows.Count ? VisibleRows[value] : null;
            }
        }
    }

    public string DetailBody => SelectedCard is null ? string.Empty : RenderCard(SelectedCard);

    private string _summary = "Not inspected yet.";

    public string Summary
    {
        get => _summary;
        private set => Set(ref _summary, value);
    }

    private string _coverage = string.Empty;

    public string Coverage
    {
        get => _coverage;
        private set => Set(ref _coverage, value);
    }

    private string _reliabilityLine = string.Empty;

    public string ReliabilityLine
    {
        get => _reliabilityLine;
        private set => Set(ref _reliabilityLine, value);
    }

    private string _minidumpLine = string.Empty;

    public string MinidumpLine
    {
        get => _minidumpLine;
        private set => Set(ref _minidumpLine, value);
    }

    private IReadOnlyList<MinidumpReport> _dumps = Array.Empty<MinidumpReport>();

    public IReadOnlyList<MinidumpReport> Dumps
    {
        get => _dumps;
        private set => Set(ref _dumps, value);
    }

    private bool _isRefreshing;

    public bool IsRefreshing
    {
        get => _isRefreshing;
        private set => Set(ref _isRefreshing, value);
    }

    public Action<AskAboutRequest>? AskAbout { get; set; }

    public Action<int>? NavigateToPage { get; set; }

    public ICommand CopyDetailsCommand { get; }

    public ICommand OpenEventViewerCommand { get; }

    public ICommand OpenDriversCommand { get; }

    public ICommand OpenStorageCommand { get; }

    public ICommand ShowRelatedCommand { get; }

    public ICommand ClearRelatedCommand { get; }

    public ICommand ReviewDiskEventsCommand { get; }

    public ICommand AskAboutThisCommand { get; }

    private readonly Func<PassportDb>? _passportFactory;

    // P26: set when snapshot persistence fails (page data is
    // unaffected); null after a successful persist or when no
    // factory is wired.
    public string? LastPersistError { get; private set; }

    // P26: passportFactory persists crash snapshots for trends.
    // Null (tests, transient views) collects without persisting.
    public CrashesViewModel(Func<PassportDb>? passportFactory = null)
    {
        _passportFactory = passportFactory;
        CopyDetailsCommand = new RelayCommand(
            _ => CopyText(DetailBody),
            _ => SelectedCard is not null);
        OpenEventViewerCommand = new RelayCommand(_ => OpenEventViewer());
        OpenDriversCommand = new RelayCommand(_ => NavigateToPage?.Invoke(3));
        OpenStorageCommand = new RelayCommand(_ => NavigateToPage?.Invoke(2));
        ShowRelatedCommand = new RelayCommand(
            _ =>
            {
                if (SelectedRow is not null)
                {
                    RelatedEventId = SelectedRow.EventId;
                }
            },
            _ => SelectedRow is not null);
        ClearRelatedCommand = new RelayCommand(_ => RelatedEventId = -1);
        ReviewDiskEventsCommand = new RelayCommand(_ => SelectedEventType = TypeDisk);
        AskAboutThisCommand = new RelayCommand(
            _ =>
            {
                if (SelectedRow is not null && SelectedCard is not null)
                {
                    AskAbout?.Invoke(new AskAboutRequest(
                        $"What caused {SelectedCard.Title} on {SelectedRow.When}?",
                        "crash", SelectedCard.Title));
                }
            },
            _ => SelectedRow is not null);
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
            // Clipboard busy — the details stay visible on screen.
        }
    }

    private static void OpenEventViewer()
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = "eventvwr.msc",
                UseShellExecute = true,
            });
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // Event Viewer unavailable — the raw event stays readable in the drawer.
        }
    }

    private static string RenderCard(CrashCard card)
    {
        var lines = new List<string> { card.Title, card.WhatHappened };
        foreach (var finding in card.Findings)
        {
            lines.Add($"Cause ({finding.Confidence}): {finding.Cause}");
            foreach (var citation in finding.Citations)
            {
                lines.Add($"  Evidence: {citation.Label}");
            }
        }

        if (card.Prevention.Count > 0)
        {
            lines.Add(string.Empty);
            lines.Add("Prevention:");
            foreach (var step in card.Prevention)
            {
                lines.Add($"• {step}");
            }
        }

        if (card.HonestGaps.Count > 0)
        {
            lines.Add(string.Empty);
            foreach (var gap in card.HonestGaps)
            {
                lines.Add("Note: " + gap);
            }
        }

        return string.Join(Environment.NewLine, lines);
    }

    // A09: routed through the versioned helper — a fault
    // records an observable error (last rows kept) instead of
    // crashing the awaiting caller, and a superseded collect
    // never Applies. Never throws.
    public Task RefreshAsync(Func<CrashesSnapshot>? collect = null)
    {
        if (IsRefreshing)
        {
            return Task.CompletedTask;
        }

        IsRefreshing = true;
        return PageRefresh.Run(
            RefreshState, collect ?? Collect, Apply, "crash history",
            PageRefresh.CaptureUiOrDefault(),
            () => IsRefreshing = false);
    }

    public void Refresh() => Apply(Collect());

    public static CrashesSnapshot Collect()
    {
        var from = DateTime.UtcNow.AddDays(-30);
        var system = EventCollector.CollectTargeted("System", null, 2, from, 200);
        var app = EventCollector.CollectTargeted("Application", null, 2, from, 200);
        // P24 (R05.5): disk + WHEA warnings are Warning-level, so the
        // errors-only reads above can never see governed IDs 153/19.
        // Provider-scoped warning reads make them reachable.
        // Informational (level 4) stays out: corrected-error noise
        // would flood the newest-first cap and hide real warnings.
        var disk = EventCollector.CollectTargeted("System", "disk", 3, from, 100);
        var whea = EventCollector.CollectTargeted(
            "System", "Microsoft-Windows-WHEA-Logger", 3, from, 100);
        var all = system.Records.Concat(app.Records).Concat(disk.Records).Concat(whea.Records)
            .GroupBy(e => (e.Log, e.RecordId))
            .Select(g => g.First())
            .ToList();
        var anchors = all
            .Where(e => e.Id is 1001 or 41 or 6008 or 1000 or 1002 or 55 or 153 or 19)
            .OrderByDescending(e => e.TimeUtc)
            .Take(50)
            .ToList();

        var cards = anchors.Select(a => CrashExplainer.Explain(a, all)).ToList();
        var rows = cards.Select((c, i) => new CrashRow(
            anchors[i].TimeUtc.ToLocalTime().ToString("g"),
            TypeFor(anchors[i]),
            Truncate(c.WhatHappened, 140),
            anchors[i].Id,
            i,
            anchors[i])).ToList();

        var problems = new List<string>();
        if (system.Status == CollectionStatus.Failed)
        {
            problems.Add("System log unreadable.");
        }

        if (app.Status == CollectionStatus.Failed)
        {
            problems.Add("Application log unreadable.");
        }

        if (disk.Status == CollectionStatus.Failed)
        {
            problems.Add("Disk warnings unreadable.");
        }

        if (whea.Status == CollectionStatus.Failed)
        {
            problems.Add("Hardware-error (WHEA) log unreadable.");
        }

        // P24: Reliability Monitor records + local minidump metadata.
        // The page analyzes at most 2 dumps per refresh: each cdb run
        // is time-bounded, but first-run symbol download can still
        // take minutes — verification legs use the wider cap.
        var reliability = ReliabilityCollector.CollectRecords(from, 200);
        var stability = ReliabilityCollector.CollectStabilityIndex(30);
        if (reliability.Status == CollectionStatus.Failed)
        {
            problems.Add("Reliability history unreadable.");
        }

        var dumps = MinidumpInspector.Inspect(maxDumps: 2);
        if (dumps.Status == CollectionStatus.Failed)
        {
            problems.Add("Crash-dump store unreadable.");
        }

        return new CrashesSnapshot(
            anchors.Count == 0
                ? "No crashes in the last 30 days."
                : $"{CountText.Of(anchors.Count, "crash event")} in the last 30 days.",
            problems.Count == 0
                ? "Inspected System + Application errors, disk + hardware-error warnings."
                : string.Join(" ", problems),
            rows, cards,
            BuildReliabilityLine(reliability, stability),
            BuildMinidumpLine(dumps),
            dumps.Records);
    }

    public static string BuildReliabilityLine(
        CollectionResult<ReliabilityRecord> reliability,
        CollectionResult<ReliabilityMetric> stability)
    {
        if (reliability.Status == CollectionStatus.Failed)
        {
            return "Reliability history could not be read — see Coverage.";
        }

        string records = reliability.Records.Count == 0
            ? "Reliability Monitor kept no records in the last 30 days."
            : $"Reliability Monitor: {CountText.Of(reliability.Records.Count, "record")} in 30 days.";
        var latest = stability.Records
            .OrderByDescending(m => m.DayUtc)
            .FirstOrDefault();
        if (latest?.StabilityIndex is double index)
        {
            records += $" Stability index {index:0.0} as of {latest.DayUtc.ToLocalTime():d}.";
        }

        return records;
    }

    public static string BuildMinidumpLine(CollectionResult<MinidumpReport> dumps)
    {
        if (dumps.Status == CollectionStatus.Failed)
        {
            return "Crash-dump store could not be read — see Coverage.";
        }

        if (dumps.Records.Count == 0)
        {
            return "No crash dumps on disk.";
        }

        var analyzed = dumps.Records.Count(r => r.Status == "Analyzed");
        var newest = dumps.Records
            .OrderByDescending(r => r.ModifiedUtc ?? DateTime.MinValue)
            .First();
        string detail = newest.Status switch
        {
            "Analyzed" => $"newest {newest.Name} (bug-check 0x{newest.BugCheckCode ?? 0:X})",
            "ToolsMissing" => $"newest {newest.Name} (Debugging Tools not installed — file list only)",
            _ => $"newest {newest.Name} ({newest.Status})",
        };
        return $"{CountText.Of(dumps.Records.Count, "crash dump")} on disk" +
            (analyzed == dumps.Records.Count ? string.Empty : $" · {analyzed} analyzed") +
            $" · {detail}.";
    }

    private static string Truncate(string text, int max)
    {
        if (string.IsNullOrEmpty(text) || text.Length <= max)
        {
            return text;
        }

        return text[..(max - 1)] + "…";
    }

    public void Apply(CrashesSnapshot s)
    {
        Summary = s.Summary;
        Coverage = s.Coverage;
        ReliabilityLine = s.ReliabilityLine;
        MinidumpLine = s.MinidumpLine;
        Dumps = s.Dumps ?? Array.Empty<MinidumpReport>();
        _cards = s.Cards;
        Timeline.Clear();
        foreach (var row in s.Rows)
        {
            Timeline.Add(row);
        }

        Weeks = BucketizeWeeks(Timeline, DateTime.UtcNow);
        RefillVisible();
        PersistSnapshots(s);
    }

    // P26: every applied collect appends its crash rows + dumps to
    // the Passport (upsert by source identity: re-collecting the
    // same event overwrites one row). Trends read back from here.
    private void PersistSnapshots(CrashesSnapshot s)
    {
        if (_passportFactory is null)
        {
            return;
        }

        try
        {
            string observed = DateTime.UtcNow.ToString("O");
            var rows = new List<CrashSnapshot>(s.Rows.Count + (s.Dumps?.Count ?? 0));
            foreach (var row in s.Rows)
            {
                var a = row.Anchor;
                rows.Add(new CrashSnapshot(
                    a.Log + ":" + a.RecordId,
                    a.TimeUtc.ToString("O"),
                    observed,
                    a.Log + "/" + a.Provider,
                    a.Id,
                    null,
                    null,
                    row.Type));
            }

            foreach (var dump in s.Dumps ?? Array.Empty<MinidumpReport>())
            {
                rows.Add(new CrashSnapshot(
                    "Dump:" + dump.Name,
                    (dump.ModifiedUtc ?? DateTime.MinValue).ToString("O"),
                    observed,
                    "Minidump",
                    0,
                    dump.BugCheckCode is uint code ? "0x" + code.ToString("X") : null,
                    dump.Module,
                    TypeCrash + " (dump)"));
            }

            using var passport = _passportFactory();
            passport.RecordCrashSnapshots(rows);
            LastPersistError = null;
        }
        catch (Exception ex)
        {
            // Persistence must never break the page: the rows on
            // screen are already collected and stay visible. The
            // failure stays observable here instead of vanishing.
            LastPersistError = ex.GetType().Name;
        }
    }

    private void RefillVisible()
    {
        var from = SelectedRange.StartsWith("Last 7", StringComparison.Ordinal)
            ? DateTime.UtcNow.AddDays(-7)
            : DateTime.MinValue;
        var ranged = Timeline.Where(r => r.Anchor.TimeUtc >= from).ToList();
        RangeRows = ranged;
        Raise(nameof(CrashCount));
        Raise(nameof(HangCount));
        Raise(nameof(DiskCount));
        Raise(nameof(UpdateCount));
        Raise(nameof(HardwareCount));

        VisibleRows.Clear();
        foreach (var row in ranged)
        {
            if (SelectedEventType != "All event types" && row.Type != SelectedEventType)
            {
                continue;
            }

            if (RelatedEventId >= 0 && row.EventId != RelatedEventId)
            {
                continue;
            }

            VisibleRows.Add(row);
        }

        if (SelectedRow is not null &&
            VisibleRows.Any(r => r.Index == SelectedRow.Index))
        {
            SelectedIndex = VisibleRows
                .Select((r, i) => (r, i))
                .First(p => p.r.Index == SelectedRow.Index).i;
        }
        else
        {
            var next = VisibleRows.Count > 0 ? VisibleRows[0] : null;
            SelectedRow = next;
            Set(ref _selectedIndex, next is null ? -1 : 0);
        }

        RefreshState.NoteSuccess();
    }

    public sealed record CrashesSnapshot(
        string Summary,
        string Coverage,
        IReadOnlyList<CrashRow> Rows,
        IReadOnlyList<CrashCard> Cards,
        string ReliabilityLine = "",
        string MinidumpLine = "",
        IReadOnlyList<MinidumpReport>? Dumps = null);
}