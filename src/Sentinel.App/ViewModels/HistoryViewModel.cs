// P1-06b board 07 (History): activity timeline + scan-runs/investigations tables +
// undo-vault honesty + JSON/HTML export. Real SentinelDb + AgentStore rows only.
// There is no action/vault backend yet, so Actions shows an honest empty state.
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Input;
using Sentinel.App.Services;
using Sentinel.Engine.Actions;
using Sentinel.Engine.Agent;
using Sentinel.Store;

namespace Sentinel.App.ViewModels;

// Everything History needs for actions + vault. Null in older
// constructions = scans/investigations only, stated honestly.
public sealed record HistoryActionServices(
    Func<ActionAuditLog> Audit,
    Func<VaultStore> Vault,
    IUndoService Undo,
    Func<int> ReviewDays,
    string VaultRoot);

public sealed class HistoryViewModel : ViewModelBase
{
    // A09: versions RefreshAsync collects; faults surface here
    // with the last lists kept.
    public RefreshTracker RefreshState { get; } = new();

    public sealed record HistoryEvent(
        string Kind,
        string Title,
        string Source,
        string Detail,
        DateTime TimeUtc,
        string TimeLine1,
        string TimeLine2,
        string StatusKind,
        ScanRunInfo? Run,
        InvestigationState? Investigation,
        IReadOnlyList<AgentFindingRecord> Findings,
        ScanRunInfo? LinkedRun,
        InvestigationState? LinkedInvestigation,
        AuditEntry? Audit = null);

    public sealed record EventGroup(string Label, string CountText, IReadOnlyList<HistoryEvent> Events);

    public sealed record RunRow(
        long Id,
        string Started,
        string Root,
        string Mode,
        string Files,
        string Gaps,
        string Elapsed,
        string Status);

    public sealed record InvestigationRow(
        string Id,
        string Updated,
        string Goal,
        string Status,
        int Findings,
        int ToolCalls,
        string Elapsed,
        string Cost);

    public sealed record HistoryFindingRow(
        string Investigation, string Status, string Observation, string Citations);

    // P25: one drawer finding with its citations rendered. The
    // drawer binds these (not raw store records) so evidence paths
    // are always redacted file names, never raw profile paths.
    public sealed record DrawerFinding(
        string Status, string Observation, string Interpretation,
        string Limitations, string Citations);

    public sealed record DrawerField(string Label, string Value);

    // One vault row for the Undo Vault tab: the manifest truth plus
    // the conflict preview (the inline conflict sheet) and a Restore
    // button that exists only for verified quarantined rows.
    public sealed class VaultRowVm : ViewModelBase
    {
        private readonly Func<string, Task> _restore;

        public VaultRowVm(VaultItem item, string conflictNote, string reviewLine, Func<string, Task> restore)
        {
            _restore = restore;
            Ref = item.Id;
            Name = Path.GetFileName(item.OriginalPath);
            OriginalPath = item.OriginalPath;
            Size = FormatBytes(item.SizeBytes);
            MovedLine = "Moved " + ParseUtc(item.MovedUtc).ToLocalTime().ToString("g");
            Status = item.Status;
            ConflictNote = conflictNote;
            ReviewLine = reviewLine;
            CanRestore = item.Status == VaultStatus.Quarantined && item.Verified;
            RestoreCommand = new RelayCommand(
                async _ => await _restore(Ref),
                _ => CanRestore && !IsRestoring);
        }

        public string Ref { get; }

        public string Name { get; }

        public string OriginalPath { get; }

        public string Size { get; }

        public string MovedLine { get; }

        public string Status { get; }

        public string ConflictNote { get; }

        public string ReviewLine { get; }

        public bool CanRestore { get; }

        private bool _isRestoring;

        public bool IsRestoring
        {
            get => _isRestoring;
            set
            {
                if (Set(ref _isRestoring, value))
                {
                    ((RelayCommand)RestoreCommand).RaiseCanExecuteChanged();
                }
            }
        }

        public ICommand RestoreCommand { get; }
    }

    public sealed record VaultRowData(VaultItem Item, string ConflictNote, string ReviewLine);

    private readonly Func<SentinelDb> _dbFactory;
    private readonly Func<AgentStore> _agentFactory;
    private readonly HistoryActionServices? _actions;
    private List<HistoryEvent> _allEvents = new();

    public IReadOnlyList<string> KindOptions { get; } =
        new[] { "All types", "Scans", "Findings", "Actions" };

    public IReadOnlyList<string> RangeOptions { get; } =
        new[] { "Last 7 days", "Last 30 days", "All time" };

    private string _selectedKind = "All types";

    public string SelectedKind
    {
        get => _selectedKind;
        set
        {
            if (Set(ref _selectedKind, value))
            {
                Refill();
            }
        }
    }

    private string _selectedRange = "Last 7 days";

    public string SelectedRange
    {
        get => _selectedRange;
        set
        {
            if (Set(ref _selectedRange, value))
            {
                Refill();
            }
        }
    }

    private int _tabIndex;

    public int TabIndex
    {
        get => _tabIndex;
        set
        {
            if (Set(ref _tabIndex, value))
            {
                Raise(nameof(IsActivityTab));
            }
        }
    }

    public bool IsActivityTab => TabIndex == 0;

    public ObservableCollection<EventGroup> Groups { get; } = new();

    public ObservableCollection<RunRow> Runs { get; } = new();

    public ObservableCollection<InvestigationRow> Investigations { get; } = new();

    public ObservableCollection<HistoryFindingRow> Findings { get; } = new();

    // E37: computed in Apply. Without action services this is the
    // original honest empty state; with services it summarizes the
    // real vault (counts + retained bytes, never freed-space fiction).
    private string _vaultState =
        "Vault is empty — no file has ever been moved here. Nothing was deleted. " +
        "This timeline shows scans and investigations; action history will appear here once actions exist.";

    public string VaultState
    {
        get => _vaultState;
        private set => Set(ref _vaultState, value);
    }

    private string _vaultTitle = "No changes to restore";

    public string VaultTitle
    {
        get => _vaultTitle;
        private set => Set(ref _vaultTitle, value);
    }

    private string _vaultNote = string.Empty;

    public string VaultNote
    {
        get => _vaultNote;
        private set => Set(ref _vaultNote, value);
    }

    private string _recoveryNote = string.Empty;

    public string RecoveryNote
    {
        get => _recoveryNote;
        private set
        {
            if (Set(ref _recoveryNote, value))
            {
                Raise(nameof(HasRecovery));
            }
        }
    }

    public bool HasRecovery => RecoveryNote.Length > 0;

    private string _auditIntegrityLine = "Integrity verification unavailable";

    public string AuditIntegrityLine
    {
        get => _auditIntegrityLine;
        private set => Set(ref _auditIntegrityLine, value);
    }

    private string _actionErrorLine = string.Empty;

    public string ActionErrorLine
    {
        get => _actionErrorLine;
        private set => Set(ref _actionErrorLine, value);
    }

    public ObservableCollection<VaultRowVm> VaultRows { get; } = new();

    private HistoryEvent? _selectedEvent;

    public HistoryEvent? SelectedEvent
    {
        get => _selectedEvent;
        set
        {
            if (Set(ref _selectedEvent, value))
            {
                Raise(nameof(HasSelection));
                Raise(nameof(DrawerTitle));
                Raise(nameof(DrawerSubtitle));
                Raise(nameof(DrawerFields));
                Raise(nameof(DrawerFindings));
                Raise(nameof(ShowFindings));
                IsFindingsExpanded = false;
            }
        }
    }

    public bool HasSelection => SelectedEvent is not null;

    public string DrawerTitle => SelectedEvent?.Title ?? string.Empty;

    public string DrawerSubtitle => SelectedEvent is null
        ? string.Empty
        : $"{SelectedEvent.TimeUtc.ToLocalTime():d MMM yyyy 'at' HH:mm} · {SelectedEvent.Source}";

    public bool ShowFindings => SelectedEvent?.Kind == "Investigation";

    private bool _isFindingsExpanded;

    public bool IsFindingsExpanded
    {
        get => _isFindingsExpanded;
        set => Set(ref _isFindingsExpanded, value);
    }

    private string _emptyText = "Loading history…";

    public string EmptyText
    {
        get => _emptyText;
        private set => Set(ref _emptyText, value);
    }

    private bool _isRefreshing;

    public bool IsRefreshing
    {
        get => _isRefreshing;
        private set => Set(ref _isRefreshing, value);
    }

    private string _exportNote = string.Empty;

    public string ExportNote
    {
        get => _exportNote;
        private set => Set(ref _exportNote, value);
    }

    public Action<int>? NavigateToPage { get; set; }

    public ICommand ViewFindingsCommand { get; }

    public ICommand ViewCoverageCommand { get; }

    public ICommand ClearKindCommand { get; }

    public HistoryViewModel(
        Func<SentinelDb> dbFactory, Func<AgentStore> agentFactory,
        HistoryActionServices? actions = null)
    {
        _dbFactory = dbFactory;
        _agentFactory = agentFactory;
        _actions = actions;
        ViewFindingsCommand = new RelayCommand(_ =>
        {
            if (SelectedEvent is null)
            {
                return;
            }

            if (SelectedEvent.Kind == "Investigation")
            {
                IsFindingsExpanded = true;
            }
            else
            {
                NavigateToPage?.Invoke(2);
            }
        });
        ViewCoverageCommand = new RelayCommand(_ => TabIndex = 1);
        ClearKindCommand = new RelayCommand(_ => SelectedKind = "All types");
    }

    public static string FormatElapsed(long durationMs)
    {
        var span = TimeSpan.FromMilliseconds(Math.Max(0, durationMs));
        if (span.TotalHours >= 1)
        {
            return $"{(int)span.TotalHours}h {span.Minutes:00}m";
        }

        if (span.TotalMinutes >= 1)
        {
            return $"{(int)span.TotalMinutes}m {span.Seconds:00}s";
        }

        return $"{(int)span.TotalSeconds}s";
    }

    public static string FormatElapsedSeconds(double seconds) =>
        FormatElapsed((long)(Math.Max(0, seconds) * 1000));

    public static string ScanTitle(string status) => status.ToLowerInvariant() switch
    {
        "completed" => "Scan completed",
        "cancelled" => "Scan cancelled",
        "failed" => "Scan failed",
        "refused" => "Scan refused",
        "running" => "Scan running",
        _ => $"Scan: {status}",
    };

    public static string InvestigationTitle(string status) => status.ToLowerInvariant() switch
    {
        "completed" => "Investigation completed",
        "cancelled" => "Investigation cancelled",
        "failed" => "Investigation failed",
        _ => $"Investigation: {status}",
    };

    public static string StatusKindFor(string status) => status.ToLowerInvariant() switch
    {
        "completed" => "Good",
        "cancelled" or "failed" => "Bad",
        _ => "Neutral",
    };

    public static (string Line1, string Line2) TimeLines(DateTime timeUtc, DateTime nowUtc)
    {
        var local = timeUtc.ToLocalTime();
        return local.Date == nowUtc.ToLocalTime().Date
            ? (local.ToString("HH:mm"), local.ToString("d MMM yyyy"))
            : (local.ToString("d MMM yyyy"), local.ToString("HH:mm"));
    }

    public static DateTime ParseUtc(string text) =>
        DateTime.TryParse(text, null, DateTimeStyles.AdjustToUniversal, out var parsed)
            ? parsed.ToUniversalTime()
            : DateTime.MinValue;

    public static IReadOnlyList<EventGroup> GroupEvents(IEnumerable<HistoryEvent> events, DateTime nowUtc)
    {
        var today = new List<HistoryEvent>();
        var week = new List<HistoryEvent>();
        var earlier = new List<HistoryEvent>();
        var todayLocal = nowUtc.ToLocalTime().Date;
        foreach (var e in events.OrderByDescending(e => e.TimeUtc))
        {
            var days = (todayLocal - e.TimeUtc.ToLocalTime().Date).Days;
            if (days <= 0)
            {
                today.Add(e);
            }
            else if (days <= 7)
            {
                week.Add(e);
            }
            else
            {
                earlier.Add(e);
            }
        }

        var groups = new List<EventGroup>();
        if (today.Count > 0)
        {
            groups.Add(new EventGroup("Today", CountText.Of(today.Count, "event"), today));
        }

        if (week.Count > 0)
        {
            groups.Add(new EventGroup("Earlier this week", CountText.Of(week.Count, "event"), week));
        }

        if (earlier.Count > 0)
        {
            groups.Add(new EventGroup("Earlier", CountText.Of(earlier.Count, "event"), earlier));
        }

        return groups;
    }

    private void Refill()
    {
        var now = DateTime.UtcNow;
        var from = SelectedRange switch
        {
            "Last 7 days" => now.AddDays(-7),
            "Last 30 days" => now.AddDays(-30),
            _ => DateTime.MinValue,
        };
        var filtered = _allEvents.Where(e => e.TimeUtc >= from).Where(e => SelectedKind switch
        {
            "Scans" => e.Kind == "Scan",
            "Findings" => e.Kind == "Investigation" && e.Findings.Count > 0,
            "Actions" => e.Kind == "Action",
            _ => true,
        }).ToList();

        Groups.Clear();
        foreach (var group in GroupEvents(filtered, now))
        {
            Groups.Add(group);
        }

        EmptyText = SelectedKind == "Actions"
            ? _actions is null
                ? "No actions yet — scans and investigations don't change your files."
                : filtered.Count == 0
                    ? "No actions recorded yet — vault moves, refusals, and restores will appear here."
                    : string.Empty
            : filtered.Count == 0
                ? "Nothing in this range yet — run a Storage scan to start a record."
                : string.Empty;

        if (SelectedEvent is not null &&
            filtered.Any(e => e.Kind == SelectedEvent.Kind
                && e.TimeUtc == SelectedEvent.TimeUtc
                && e.Title == SelectedEvent.Title))
        {
            return;
        }

        SelectedEvent = Groups.Count > 0 && Groups[0].Events.Count > 0
            ? Groups[0].Events[0]
            : null;
    }

    // A09: routed through the versioned helper — a fault
    // records an observable error (last lists kept) instead of
    // crashing the awaiting caller, and a superseded collect
    // never Applies. Never throws.
    public Task RefreshAsync(Func<HistorySnapshot>? collect = null)
    {
        if (IsRefreshing)
        {
            return Task.CompletedTask;
        }

        IsRefreshing = true;
        return PageRefresh.Run(
            RefreshState, collect ?? Collect, Apply, "history",
            PageRefresh.CaptureUiOrDefault(),
            () => IsRefreshing = false);
    }

    public void Refresh() => Apply(Collect());

    public void Apply(HistorySnapshot snapshot)
    {
        _allEvents = snapshot.Events;
        Runs.Clear();
        foreach (var row in snapshot.Runs)
        {
            Runs.Add(row);
        }

        Investigations.Clear();
        foreach (var row in snapshot.Investigations)
        {
            Investigations.Add(row);
        }

        Findings.Clear();
        foreach (var row in snapshot.Findings)
        {
            Findings.Add(row);
        }

        VaultRows.Clear();
        foreach (var row in snapshot.VaultRows)
        {
            VaultRows.Add(new VaultRowVm(row.Item, row.ConflictNote, row.ReviewLine, RestoreVaultItem));
        }

        VaultState = snapshot.VaultState;
        VaultTitle = snapshot.VaultTitle;
        RecoveryNote = snapshot.RecoveryNote;
        AuditIntegrityLine = snapshot.AuditIntegrityLine;
        ActionErrorLine = snapshot.ActionError;

        Refill();
        RefreshState.NoteSuccess();
    }

    public sealed record HistorySnapshot(
        List<HistoryEvent> Events,
        IReadOnlyList<RunRow> Runs,
        IReadOnlyList<InvestigationRow> Investigations,
        IReadOnlyList<HistoryFindingRow> Findings,
        string VaultState,
        string VaultTitle,
        IReadOnlyList<VaultRowData> VaultRows,
        string RecoveryNote,
        string AuditIntegrityLine,
        string ActionError);

    public HistorySnapshot Collect()
    {
        using var scanDb = _dbFactory();
        using var agentDb = _agentFactory();
        var runs = scanDb.ListRuns(200);
        var investigations = agentDb.ListInvestigations(50);
        var now = DateTime.UtcNow;
        var events = new List<HistoryEvent>();

        foreach (var run in runs)
        {
            var time = ParseUtc(run.StartedUtc);
            var (line1, line2) = TimeLines(time, now);
            var linked = investigations.FirstOrDefault(i => i.CommittedGeneration == run.Generation);
            string detail = run.Status.ToLowerInvariant() switch
            {
                "cancelled" => $"Partial results · Stopped by user after {FormatElapsed(run.DurationMs)}",
                "failed" => string.IsNullOrWhiteSpace(run.Error)
                    ? "Failed before finishing"
                    : $"Failed: {run.Error}",
                "refused" => string.IsNullOrWhiteSpace(run.Error)
                    ? "Refused by the scan governor"
                    : $"Refused: {run.Error}",
                _ => $"{run.Mode} · {run.Root} · {CountText.Of(run.FilesSeen, "file")} · {CountText.Of(run.GapsCount, "gap")} · {FormatElapsed(run.DurationMs)}",
            };
            events.Add(new HistoryEvent(
                "Scan", ScanTitle(run.Status),
                run.Status.Equals("Cancelled", StringComparison.OrdinalIgnoreCase) ? "You" : "Local collector",
                detail, time, line1, line2, StatusKindFor(run.Status),
                run, null, Array.Empty<AgentFindingRecord>(), run, linked));
        }

        foreach (var inv in investigations)
        {
            var time = ParseUtc(inv.UpdatedUtc);
            var (line1, line2) = TimeLines(time, now);
            var findings = agentDb.GetFindings(inv.Id);
            var linkedRun = runs.FirstOrDefault(r => r.Generation == inv.CommittedGeneration);
            string coverage = linkedRun is null
                ? "Coverage unknown (scan record missing)"
                : linkedRun.GapsCount == 0
                    ? "Full coverage"
                    : $"Partial coverage ({CountText.Of(linkedRun.GapsCount, "gap")})";
            events.Add(new HistoryEvent(
                "Investigation", InvestigationTitle(inv.Status), "AI investigation",
                $"{CountText.Of(findings.Count, "finding")} with evidence · {coverage}",
                time, line1, line2, StatusKindFor(inv.Status),
                null, inv, findings, linkedRun, inv));
        }

        var runRows = runs.Select(r => new RunRow(
            r.Id,
            ParseUtc(r.StartedUtc).ToLocalTime().ToString("g"),
            r.Root, r.Mode,
            r.FilesSeen.ToString("n0", CultureInfo.CurrentCulture),
            r.GapsCount.ToString(CultureInfo.CurrentCulture),
            FormatElapsed(r.DurationMs),
            r.Status)).ToList();
        var invRows = investigations.Select(i => new InvestigationRow(
            i.Id,
            ParseUtc(i.UpdatedUtc).ToLocalTime().ToString("g"),
            string.IsNullOrWhiteSpace(i.Goal) ? "(no goal recorded)" : i.Goal,
            string.IsNullOrWhiteSpace(i.StatusDetail) ? i.Status : $"{i.Status} — {i.StatusDetail}",
            agentDb.GetFindings(i.Id).Count,
            i.ToolCalls,
            FormatElapsedSeconds(i.ElapsedSeconds),
            CostLabel(i.EstimatedCostUsd))).ToList();
        var findingRows = new List<HistoryFindingRow>();
        foreach (var inv in investigations)
        {
            foreach (var finding in agentDb.GetFindings(inv.Id))
            {
                findingRows.Add(new HistoryFindingRow(
                    inv.Goal, finding.Status, finding.Observation,
                    FormatCitations(finding.EvidenceIdsJson)));
            }
        }

        // E37: actions + vault ride alongside scans/investigations.
        // Their failures land on ActionErrorLine with the other lists
        // kept — a broken audit store must not hide scan history.
        // Reconcile runs here (idempotent, read-mostly): every History
        // visit surfaces crash residue instead of only cold starts.
        string vaultState = VaultState;
        string vaultTitle = VaultTitle;
        var vaultRows = new List<VaultRowData>();
        string recoveryNote = string.Empty;
        string integrityLine = "Integrity verification unavailable";
        string actionError = string.Empty;
        if (_actions is not null)
        {
            try
            {
                using var audit = _actions.Audit();
                using var vault = _actions.Vault();
                var integrity = audit.VerifyChain();
                integrityLine = integrity.Ok
                    ? "Audit integrity OK — " + integrity.Detail
                    : "Audit integrity BROKEN — " + integrity.Detail;
                foreach (var entry in audit.ListRecent(200))
                {
                    var time = ParseUtc(entry.Utc);
                    var (line1, line2) = TimeLines(time, now);
                    var (detail, _) = ActionAuditLog.SplitAfter(entry.AfterJson);
                    events.Add(new HistoryEvent(
                        "Action", ActionEventTitle(entry, detail), ActorLabel(entry.Actor),
                        detail, time, line1, line2, ActionStatusKind(detail, entry.UndoState),
                        null, null, Array.Empty<AgentFindingRecord>(), null, null, entry));
                }

                var report = vault.ReconcileInterrupted(
                    _actions.VaultRoot, new DiskVaultFileIO().ComputeSha256,
                    now.ToString("o"));
                if (report.Findings.Count > 0)
                {
                    recoveryNote = RecoveryText(report);
                }

                int reviewDays = _actions.ReviewDays();
                foreach (var item in vault.ListAll())
                {
                    vaultRows.Add(new VaultRowData(item,
                        ConflictNoteFor(item), ReviewLineFor(item, reviewDays, now)));
                }

                long retained = vault.QueryRetainedBytes();
                int restorable = vaultRows.Count(r =>
                    r.Item.Status == VaultStatus.Quarantined && r.Item.Verified);
                if (vaultRows.Count == 0)
                {
                    vaultState = "Vault is empty — no file has ever been moved here. Nothing was deleted.";
                    vaultTitle = "No changes to restore";
                }
                else
                {
                    vaultState = $"{CountText.Of(vaultRows.Count, "file")} in the Vault · " +
                        $"{FormatBytes(retained)} retained (not freed space — same-volume moves) · " +
                        "reviewed, never auto-deleted.";
                    vaultTitle = restorable == vaultRows.Count
                        ? $"{CountText.Of(restorable, "file")} in Vault — all restorable"
                        : $"{CountText.Of(vaultRows.Count, "file")} in Vault — {restorable} restorable";
                }
            }
            catch (Exception ex)
            {
                actionError = $"Actions and vault are unavailable right now ({ex.GetType().Name}): {ex.Message} — " +
                    "scans and investigations below are unaffected.";
            }
        }

        return new HistorySnapshot(
            events.OrderByDescending(e => e.TimeUtc).ToList(), runRows, invRows, findingRows,
            vaultState, vaultTitle, vaultRows, recoveryNote, integrityLine, actionError);
    }

    public static string ActorLabel(string actor) => actor switch
    {
        ActionActors.User => "You",
        ActionActors.Scheduled => "Scheduled run",
        ActionActors.AgentProposedUserApproved => "AI proposed · you approved",
        _ => actor,
    };

    public static string ActionEventTitle(AuditEntry entry, string detail)
    {
        if (detail.StartsWith("[Undo]", StringComparison.Ordinal))
        {
            return "Restored from Vault";
        }

        string action = entry.ActionId switch
        {
            "clean_items_to_vault" => "Vault move",
            _ => entry.ActionId,
        };
        string tag = TagOf(detail);
        if (tag.StartsWith("Completed", StringComparison.Ordinal))
        {
            return action + " completed";
        }

        if (tag.StartsWith("Partial", StringComparison.Ordinal))
        {
            return action + " partially completed";
        }

        if (tag.StartsWith("Refused", StringComparison.Ordinal))
        {
            return action + " refused";
        }

        if (tag.StartsWith("Failed", StringComparison.Ordinal))
        {
            return action + " failed safely";
        }

        if (tag.StartsWith("Cancelled", StringComparison.Ordinal))
        {
            return action + " cancelled";
        }

        if (tag.StartsWith("Duplicate", StringComparison.Ordinal))
        {
            return action + " already ran";
        }

        return action;
    }

    public static string ActionStatusKind(string detail, string undoState)
    {
        string tag = TagOf(detail);
        if (detail.StartsWith("[Undo]", StringComparison.Ordinal) ||
            undoState.Equals("Undone", StringComparison.Ordinal))
        {
            return "Good";
        }

        if (tag.StartsWith("Completed", StringComparison.Ordinal))
        {
            return "Good";
        }

        if (tag.StartsWith("Failed", StringComparison.Ordinal))
        {
            return "Bad";
        }

        return "Neutral";
    }

    private static string TagOf(string detail)
    {
        if (!detail.StartsWith("[", StringComparison.Ordinal))
        {
            return string.Empty;
        }

        int end = detail.IndexOf(']');
        return end <= 1 ? string.Empty : detail.Substring(1, end - 1);
    }

    public static string ConflictNoteFor(VaultItem item)
    {
        if (item.Status != VaultStatus.Quarantined || !item.Verified)
        {
            return item.Status switch
            {
                VaultStatus.Restored => "Already restored.",
                VaultStatus.InterruptedMove or VaultStatus.InterruptedRestore =>
                    "Interrupted — see the recovery note above.",
                VaultStatus.Superseded => "Superseded by a later decision.",
                _ => "Not restorable in its current state.",
            };
        }

        string dest = VaultLayout.RestoreConflictPath(item.OriginalPath, File.Exists);
        return string.Equals(dest, item.OriginalPath, StringComparison.OrdinalIgnoreCase)
            ? string.Empty
            : $"A file is already at the original path — restore will place this beside it as '{Path.GetFileName(dest)}'. " +
              "Your data will not be overwritten.";
    }

    public static string ReviewLineFor(VaultItem item, int reviewDays, DateTime nowUtc)
    {
        if (item.Status != VaultStatus.Quarantined)
        {
            return string.Empty;
        }

        var due = ParseUtc(item.MovedUtc).AddDays(Math.Max(1, reviewDays));
        if (nowUtc <= due)
        {
            return $"Review due {due.ToLocalTime():d MMM yyyy} — a flag only, never auto-deleted.";
        }

        int overdue = (int)Math.Max(1, (nowUtc - due).TotalDays);
        return $"Review overdue by {overdue} {(overdue == 1 ? "day" : "days")} — kept (never auto-deleted).";
    }

    public static string RecoveryText(RecoveryReport report)
    {
        var parts = new List<string>();
        if (report.BookkeepingCompleted > 0)
        {
            parts.Add($"Recovered {CountText.Of(report.BookkeepingCompleted, "vault record")} from an interrupted session.");
        }

        if (report.NeedsUserDecision > 0)
        {
            parts.Add($"{CountText.Of(report.NeedsUserDecision, "item")} " +
                $"{(report.NeedsUserDecision == 1 ? "needs" : "need")} your decision — see the Vault tab.");
        }

        if (report.BytesMissing > 0)
        {
            parts.Add($"{CountText.Of(report.BytesMissing, "item")}'s bytes are missing and cannot be recovered from the vault.");
        }

        return string.Join(" ", parts);
    }

    public static string CostLabel(double? estimatedCostUsd) =>
        estimatedCostUsd is null ? "Cost estimate unavailable" : $"${estimatedCostUsd:F4}";

    // P25: renders a finding's EvidenceIdsJson as citable evidence.
    // File NAMES only (never raw profile paths), redacted like any
    // boundary text. Corrupt JSON is stated, never hidden: Resume
    // skips such findings, but History still shows the row.
    public static string FormatCitations(string evidenceIdsJson)
    {
        List<string> names = new();
        try
        {
            using var doc = JsonDocument.Parse(evidenceIdsJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Array)
            {
                return "Evidence list unreadable";
            }

            foreach (var el in doc.RootElement.EnumerateArray())
            {
                string path = el.TryGetProperty("path", out var p)
                    && p.ValueKind == JsonValueKind.String
                    ? p.GetString() ?? string.Empty
                    : string.Empty;
                string name = Path.GetFileName(path);
                if (string.IsNullOrEmpty(name))
                {
                    name = "(unnamed)";
                }

                names.Add(SecretRedactor.RedactUserPrefix(name));
            }
        }
        catch (JsonException)
        {
            return "Evidence list unreadable";
        }

        return names.Count == 0
            ? "No evidence cited"
            : "Evidence: " + string.Join(", ", names);
    }

    // R14.1: token counts are the provider's report, shown only when
    // one arrived — never zeros dressed as measurements.
    public static string TokenLabel(InvestigationState inv) =>
        !inv.HasProviderUsage
            ? "Token counts unavailable"
            : $"{inv.InputTokens:N0} in · {inv.OutputTokens:N0} out" +
              (inv.ReasoningTokens > 0 ? $" · {inv.ReasoningTokens:N0} reasoning" : string.Empty) +
              (inv.CachedTokens > 0 ? $" · {inv.CachedTokens:N0} cached" : string.Empty);

    // P25: the selected investigation's findings with citations
    // rendered (redacted names, never raw paths). Projected on
    // demand; finding lists are small.
    public IReadOnlyList<DrawerFinding> DrawerFindings =>
        SelectedEvent?.Findings
            .Select(f => new DrawerFinding(
                f.Status, f.Observation, f.Interpretation,
                f.Limitations, FormatCitations(f.EvidenceIdsJson)))
            .ToList()
        ?? (IReadOnlyList<DrawerFinding>)Array.Empty<DrawerFinding>();

    public IReadOnlyList<DrawerField> DrawerFields
    {
        get
        {
            var e = SelectedEvent;
            if (e is null)
            {
                return Array.Empty<DrawerField>();
            }

            if (e.Kind == "Action" && e.Audit is not null)
            {
                var entry = e.Audit;
                var (detail, _) = ActionAuditLog.SplitAfter(entry.AfterJson);
                return new[]
                {
                    new DrawerField("Actor", ActorLabel(entry.Actor)),
                    new DrawerField("Action", entry.ActionId),
                    new DrawerField("What happened", detail),
                    new DrawerField("Backup", entry.BackupRef),
                    new DrawerField("Undo state", entry.UndoState),
                    new DrawerField("Evidence hash", entry.EvidenceHash ?? "none recorded"),
                    new DrawerField("Recorded", ParseUtc(entry.Utc).ToLocalTime().ToString("g")),
                    new DrawerField("Versions",
                        $"app {entry.AppVersion} · model {entry.ModelId} · pack {entry.PackVersion}"),
                    new DrawerField("Entry", $"seq {entry.Seq} · {ShortHash(entry.EntryHash)}"),
                };
            }

            if (e.Kind == "Investigation" && e.Investigation is not null)
            {
                var inv = e.Investigation;
                return new[]
                {
                    new DrawerField("Goal", string.IsNullOrWhiteSpace(inv.Goal) ? "(no goal recorded)" : inv.Goal),
                    new DrawerField("Status", string.IsNullOrWhiteSpace(inv.StatusDetail) ? inv.Status : $"{inv.Status} — {inv.StatusDetail}"),
                    new DrawerField("Findings", e.Findings.Count.ToString(CultureInfo.CurrentCulture)),
                    new DrawerField("Tool calls", inv.ToolCalls.ToString(CultureInfo.CurrentCulture)),
                    new DrawerField("Evidence kept", FormatBytes(inv.EvidenceBytes)),
                    new DrawerField("Sent on the wire", FormatBytes(inv.TransmittedBytes)),
                    new DrawerField("Provider tokens", TokenLabel(inv)),
                    new DrawerField("Elapsed time", FormatElapsedSeconds(inv.ElapsedSeconds)),
                    new DrawerField("Estimated cost", CostLabel(inv.EstimatedCostUsd)),
                    new DrawerField("Scan generation", inv.CommittedGeneration.ToString(CultureInfo.CurrentCulture)),
                };
            }

            if (e.Run is not null)
            {
                var run = e.Run;
                string collection = run.Status.ToLowerInvariant() switch
                {
                    "completed" => run.GapsCount == 0 ? "Complete" : "Complete with gaps",
                    "cancelled" => "Cancelled by user",
                    "failed" => string.IsNullOrWhiteSpace(run.Error) ? "Failed" : $"Failed: {run.Error}",
                    "refused" => "Refused by the governor",
                    _ => run.Status,
                };
                return new[]
                {
                    new DrawerField("Scan mode", run.Mode),
                    new DrawerField("Scan root", run.Root),
                    new DrawerField("Generation", run.Generation.ToString(CultureInfo.CurrentCulture)),
                    new DrawerField("Collection status", collection),
                    new DrawerField("AI status", e.LinkedInvestigation?.Status ?? "Not run"),
                    new DrawerField("Files observed", run.FilesSeen.ToString("n0", CultureInfo.CurrentCulture)),
                    new DrawerField("Gaps", run.GapsCount.ToString(CultureInfo.CurrentCulture)),
                    new DrawerField("Elapsed time", FormatElapsed(run.DurationMs)),
                };
            }

            return Array.Empty<DrawerField>();
        }
    }

    public static string FormatBytes(long bytes)
    {
        if (bytes < 1024)
        {
            return $"{bytes} B";
        }

        double kb = bytes / 1024.0;
        return kb < 1024 ? $"{kb:0.#} KB" : $"{kb / 1024.0:0.#} MB";
    }

    public static string ShortHash(string hash) =>
        hash.Length <= 16 ? hash : hash.Substring(0, 16) + "…";

    // E37: restores one vault item. Only verified quarantined rows
    // offer this (CanRestore); after a restore the page re-collects
    // so the new Undo audit entry appears in the timeline.
    public async Task RestoreVaultItem(string vaultRef)
    {
        if (_actions is null)
        {
            VaultNote = "Restore is unavailable in this build.";
            return;
        }

        var row = VaultRows.FirstOrDefault(r => r.Ref == vaultRef);
        if (row is null || !row.CanRestore)
        {
            VaultNote = "That item is not restorable.";
            return;
        }

        row.IsRestoring = true;
        try
        {
            var results = await _actions.Undo.RestoreAsync([vaultRef], CancellationToken.None);
            var result = results.FirstOrDefault();
            if (result is not null && result.Restored)
            {
                VaultNote = result.Detail;
                Refresh();
            }
            else
            {
                VaultNote = result?.Detail ?? "Restore failed.";
            }
        }
        catch (Exception ex)
        {
            VaultNote = $"Restore failed ({ex.GetType().Name}): {ex.Message} — the vault still holds the bytes.";
        }
        finally
        {
            row.IsRestoring = false;
        }
    }

    public void JumpToRun(long id)
    {
        var target = _allEvents.FirstOrDefault(e => e.Kind == "Scan" && e.Run?.Id == id);
        if (target is not null)
        {
            SelectedKind = "All types";
            SelectedRange = "All time";
            TabIndex = 0;
            SelectedEvent = target;
        }
    }

    public void JumpToInvestigation(string id)
    {
        var target = _allEvents.FirstOrDefault(e => e.Kind == "Investigation" && e.Investigation?.Id == id);
        if (target is not null)
        {
            SelectedKind = "All types";
            SelectedRange = "All time";
            TabIndex = 0;
            SelectedEvent = target;
        }
    }

    public string BuildAuditJson()
    {
        var snapshot = Collect();
        var payload = new Dictionary<string, object?>
        {
            ["generatedUtc"] = DateTime.UtcNow.ToString("o"),
            ["machine"] = Environment.MachineName,
            ["runs"] = snapshot.Runs,
            ["investigations"] = snapshot.Investigations,
            ["findings"] = snapshot.Findings,
            ["vault"] = VaultState,
        };
        if (_actions is not null)
        {
            try
            {
                using var audit = _actions.Audit();
                using var vault = _actions.Vault();
                var integrity = audit.VerifyChain();
                payload["integrity"] = new
                {
                    ok = integrity.Ok,
                    brokenAtSeq = integrity.BrokenAtSeq,
                    detail = integrity.Detail,
                };
                payload["actions"] = audit.ListRecent(500).Select(e =>
                {
                    var (detail, afterJson) = ActionAuditLog.SplitAfter(e.AfterJson);
                    return new
                    {
                        seq = e.Seq,
                        utc = e.Utc,
                        actor = e.Actor,
                        actionId = e.ActionId,
                        detail,
                        afterJson,
                        backupRef = e.BackupRef,
                        undoState = e.UndoState,
                        entryHash = e.EntryHash,
                    };
                }).ToList();
                payload["vaultItems"] = vault.ListAll().Select(i => new
                {
                    id = i.Id,
                    originalPath = i.OriginalPath,
                    sizeBytes = i.SizeBytes,
                    movedUtc = i.MovedUtc,
                    status = i.Status,
                    verified = i.Verified,
                    restoredPath = i.RestoredPath,
                }).ToList();
                payload["retainedBytes"] = vault.QueryRetainedBytes();
            }
            catch (Exception ex)
            {
                payload["actionsError"] = $"{ex.GetType().Name}: {ex.Message}";
            }
        }

        return JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
    }

    public string BuildAuditHtml()
    {
        using var scanDb = _dbFactory();
        using var agentDb = _agentFactory();
        var runs = scanDb.ListRuns(200);
        var investigations = agentDb.ListInvestigations(50);
        var html = new StringBuilder();
        html.Append("<!DOCTYPE html><html><head><meta charset=\"utf-8\">");
        html.Append("<title>Sentinel history export</title>");
        html.Append("<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#111}");
        html.Append("table{border-collapse:collapse;margin:12px 0}th,td{border:1px solid #999;padding:4px 10px;text-align:left}");
        html.Append("h1{font-size:20px}h2{font-size:16px;margin-top:24px}</style></head><body>");
        html.Append("<h1>Sentinel history</h1>");
        html.Append($"<p>Machine: {HtmlEncode(Environment.MachineName)} · Exported: {DateTime.UtcNow:u}</p>");
        html.Append("<h2>Scan runs</h2><table><tr><th>Started (UTC)</th><th>Root</th><th>Mode</th><th>Files</th><th>Gaps</th><th>Elapsed</th><th>Status</th></tr>");
        foreach (var run in runs)
        {
            html.Append("<tr><td>").Append(HtmlEncode(run.StartedUtc)).Append("</td><td>")
                .Append(HtmlEncode(run.Root)).Append("</td><td>")
                .Append(HtmlEncode(run.Mode)).Append("</td><td>")
                .Append(run.FilesSeen).Append("</td><td>")
                .Append(run.GapsCount).Append("</td><td>")
                .Append(HtmlEncode(FormatElapsed(run.DurationMs))).Append("</td><td>")
                .Append(HtmlEncode(run.Status)).Append("</td></tr>");
        }

        html.Append("</table><h2>Investigations</h2>");
        html.Append("<table><tr><th>Updated (UTC)</th><th>Goal</th><th>Status</th><th>Findings</th><th>Tool calls</th><th>Elapsed</th></tr>");
        foreach (var inv in investigations)
        {
            html.Append("<tr><td>").Append(HtmlEncode(inv.UpdatedUtc)).Append("</td><td>")
                .Append(HtmlEncode(inv.Goal)).Append("</td><td>")
                .Append(HtmlEncode(inv.Status)).Append("</td><td>")
                .Append(agentDb.GetFindings(inv.Id).Count).Append("</td><td>")
                .Append(inv.ToolCalls).Append("</td><td>")
                .Append(HtmlEncode(FormatElapsedSeconds(inv.ElapsedSeconds))).Append("</td></tr>");
        }

        html.Append("</table><h2>Findings</h2>");
        html.Append("<table><tr><th>Investigation</th><th>Status</th><th>Observation</th></tr>");
        foreach (var inv in investigations)
        {
            foreach (var finding in agentDb.GetFindings(inv.Id))
            {
                html.Append("<tr><td>").Append(HtmlEncode(inv.Goal)).Append("</td><td>")
                    .Append(HtmlEncode(finding.Status)).Append("</td><td>")
                    .Append(HtmlEncode(finding.Observation)).Append("</td></tr>");
            }
        }

        html.Append("</table><h2>Undo Vault</h2>");
        html.Append($"<p>{HtmlEncode(VaultState)}</p>");
        if (_actions is not null)
        {
            try
            {
                using var audit = _actions.Audit();
                using var vault = _actions.Vault();
                var integrity = audit.VerifyChain();
                html.Append("<h2>Audit integrity</h2><p>");
                html.Append(integrity.Ok ? "OK — " : "BROKEN — ");
                html.Append(HtmlEncode(integrity.Detail)).Append("</p>");
                html.Append("<h2>Actions</h2>");
                html.Append("<table><tr><th>Seq</th><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Detail</th><th>Backup</th><th>Undo</th></tr>");
                foreach (var entry in audit.ListRecent(500))
                {
                    var (detail, _) = ActionAuditLog.SplitAfter(entry.AfterJson);
                    html.Append("<tr><td>").Append(entry.Seq).Append("</td><td>")
                        .Append(HtmlEncode(entry.Utc)).Append("</td><td>")
                        .Append(HtmlEncode(ActorLabel(entry.Actor))).Append("</td><td>")
                        .Append(HtmlEncode(entry.ActionId)).Append("</td><td>")
                        .Append(HtmlEncode(detail)).Append("</td><td>")
                        .Append(HtmlEncode(entry.BackupRef)).Append("</td><td>")
                        .Append(HtmlEncode(entry.UndoState)).Append("</td></tr>");
                }

                html.Append("</table><h2>Vault items</h2>");
                html.Append("<table><tr><th>ID</th><th>Original path</th><th>Size</th><th>Moved (UTC)</th><th>Status</th><th>Restored to</th></tr>");
                foreach (var item in vault.ListAll())
                {
                    html.Append("<tr><td>").Append(HtmlEncode(item.Id)).Append("</td><td>")
                        .Append(HtmlEncode(item.OriginalPath)).Append("</td><td>")
                        .Append(item.SizeBytes).Append("</td><td>")
                        .Append(HtmlEncode(item.MovedUtc)).Append("</td><td>")
                        .Append(HtmlEncode(item.Status)).Append("</td><td>")
                        .Append(HtmlEncode(item.RestoredPath ?? string.Empty)).Append("</td></tr>");
                }

                html.Append("</table>");
            }
            catch (Exception ex)
            {
                html.Append("<h2>Actions</h2><p>Unavailable: ")
                    .Append(HtmlEncode($"{ex.GetType().Name}: {ex.Message}")).Append("</p>");
            }
        }

        html.Append("</body></html>");
        return html.ToString();
    }

    private static string HtmlEncode(string text) =>
        text.Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal);

    public bool WriteExport(string path, string kind)
    {
        try
        {
            string content = kind.Equals("html", StringComparison.OrdinalIgnoreCase)
                ? BuildAuditHtml()
                : BuildAuditJson();
            File.WriteAllText(path, content, Encoding.UTF8);
            ExportNote = $"Exported {Path.GetFileName(path)}.";
            return true;
        }
        catch (IOException)
        {
            ExportNote = "Export failed — the file could not be written.";
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            ExportNote = "Export failed — access denied for that location.";
            return false;
        }
    }
}