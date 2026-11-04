using System.Collections.ObjectModel;
using System.Windows.Input;
using Sentinel.Engine.Actions;
using Sentinel.Engine.Drivers;
using Sentinel.Engine.Policy;

namespace Sentinel.App.ViewModels;

public sealed record DriverSheetRow(
    string DeviceName,
    string ChangeLine,
    string SourceLine,
    string DetailLine);

// D43: the driver sheet — the E33 pattern for device targets.
// Preview → Running → Done, one exact device list, one Confirm for
// exactly that list, honest progress with real cancellation.
// Differences from the clean sheet, all deliberate:
//   - Backup is a Windows restore point (+ automatic reinstall of
//     the previous driver on verification failure), not the Vault.
//   - There is NO Undo button: update rows are undone by the
//     rollback action (offered from the Drivers page), and the
//     outcome says so. A vault-restore button here would lie.
//   - Outcome titles NEVER say "fixed": Refused reports "No changes
//     made", Partial names the split, Failed reports "Failed
//     safely". Per-row truth rides in the rows, not the title.
//   - Restart state is derived from installer evidence ("reboot is
//     pending" in an outcome detail), never assumed.
public sealed class DriverSheetViewModel : ViewModelBase
{
    private readonly ActionTemplate _template;
    private readonly Func<ActionDispatcher> _dispatcher;
    private readonly bool _isRollback;
    private readonly IReadOnlyList<DriverSheetApprovalRow> _approvals;
    private CancellationTokenSource? _runCts;
    private Task? _runTask;

    private sealed record DriverSheetApprovalRow(
        string BrokerId, string DeviceId, string DeviceName, string AuxJson);

    public DriverSheetViewModel(
        DriverPreview preview,
        ActionTemplate template,
        Func<ActionDispatcher> dispatcher)
    {
        _template = template;
        _dispatcher = dispatcher;
        _isRollback = false;
        PreviewedUtc = preview.PreviewedUtc;
        IsRefusedPreview = preview.RefusedReason is not null;
        RefusedReason = preview.RefusedReason;

        var approvals = new List<DriverSheetApprovalRow>();
        foreach (var item in preview.Included)
        {
            Included.Add(new DriverSheetRow(
                item.DeviceName,
                $"{item.InstalledVersion} → {item.Candidate.Version}",
                $"{SourceLabel(item.Candidate.Source)}" +
                    (item.Candidate.CatalogueId is null ? string.Empty : $" · {item.Candidate.CatalogueId}"),
                item.WhyEligible));
            var aux = new DriverTargetAux(
                null, null, null,
                SourceName(item.Candidate.Source),
                item.Candidate.Version,
                item.Candidate.CatalogueId,
                null, null);
            approvals.Add(new DriverSheetApprovalRow(
                item.BrokerId, item.DeviceId, item.DeviceName, aux.ToJson()));
        }

        if (preview.OemSet is not null)
        {
            OemSet = preview.OemSet;
            var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var item in preview.Included)
            {
                names.TryAdd(item.DeviceId, item.DeviceName);
            }

            foreach (var device in preview.Unsupported)
            {
                names.TryAdd(device.DeviceId, device.DeviceName);
            }

            foreach (string deviceId in preview.OemSet.DeviceIds)
            {
                string name = names.TryGetValue(deviceId, out string? known) ? known : deviceId;
                Included.Add(new DriverSheetRow(
                    name,
                    "OEM catalogue set",
                    $"{preview.OemSet.VendorName} · {preview.OemSet.Titles.Count} update(s)",
                    preview.OemSet.Summary));
                var aux = new DriverTargetAux(
                    null, null, null, "oem-catalogue", null, null, null, null);
                approvals.Add(new DriverSheetApprovalRow(
                    "dev:" + deviceId, deviceId, name, aux.ToJson()));
            }
        }

        foreach (var device in preview.Unsupported)
        {
            Unsupported.Add(device);
        }

        OemNote = preview.OemNote;
        _approvals = approvals;
        InitCommands();
    }

    public DriverSheetViewModel(
        DriverRollbackPreview preview,
        ActionTemplate template,
        Func<ActionDispatcher> dispatcher)
    {
        _template = template;
        _dispatcher = dispatcher;
        _isRollback = true;
        PreviewedUtc = preview.PreviewedUtc;
        IsRefusedPreview = preview.RefusedReason is not null;
        RefusedReason = preview.RefusedReason;

        var approvals = new List<DriverSheetApprovalRow>();
        foreach (var item in preview.Included)
        {
            Included.Add(new DriverSheetRow(
                item.DeviceName,
                $"{item.BadVersion} → {item.PreviousVersion}",
                $"Reinstall {item.TargetInf} from the driver store",
                item.BadSource == "unknown"
                    ? "The bad version came from an unknown channel — it will be blocked on every installable channel."
                    : $"The bad version came from {item.BadSource} — it will be blocked there."));
            var aux = new DriverTargetAux(
                item.TargetInf, item.PreviousVersion, null,
                item.BadSource, null, null, item.TargetInf, item.BadVersion);
            approvals.Add(new DriverSheetApprovalRow(
                item.BrokerId, item.DeviceId, item.DeviceName, aux.ToJson()));
        }

        foreach (var device in preview.Unsupported)
        {
            Unsupported.Add(device);
        }

        _approvals = approvals;
        InitCommands();
    }

    public event Action? CloseRequested;

    public Action? ViewHistory { get; set; }

    public bool HasViewHistory => ViewHistory is not null;

    public ObservableCollection<DriverSheetRow> Included { get; } = [];

    public ObservableCollection<DriverUnsupportedDevice> Unsupported { get; } = [];

    public ObservableCollection<SheetOutcomeRow> ItemResults { get; } = [];

    public DriverOemSet? OemSet { get; }

    public string? OemNote { get; }

    public bool HasOemNote => OemNote is not null;

    public bool HasUnsupported => Unsupported.Count > 0;

    public DateTime PreviewedUtc { get; }

    public string ActionTitle => _template.Title;

    public string CountLine =>
        _isRollback
            ? $"{Included.Count} device(s) to roll back"
            : OemSet is not null
                ? $"{OemSet.Titles.Count} catalogue update(s) for {Included.Count} device(s) — one set"
                : $"{Included.Count} device(s) to update";

    public string AsOfLine => $"Previewed {PreviewedUtc.ToLocalTime():g} · re-checked at execution";

    public string BackupLine =>
        "Backup: a Windows restore point is created before any change (its sequence is shown " +
        "in the outcome). A failed update automatically reinstalls the previous driver; " +
        "a failed rollback keeps its restore point for manual recovery in System Restore.";

    public string PermissionLine =>
        "Permission: Drivers L2 — Fix with approval. This confirmation approves exactly " +
        "the devices listed above, and only the versions shown.";

    public string ElevationLine =>
        IsRefusedPreview && RefusedReason is not null && RefusedReason.Contains("administrator")
            ? RefusedReason
            : "Running as administrator — elevation verified for this run.";

    public string RestartLine =>
        "Driver changes may need a restart. The installer says so in the outcome — " +
        "Sentinel never restarts your PC by itself.";

    public string LimitationsLine =>
        _isRollback
            ? "Rollback reinstalls a driver-store package and verifies the bad version is gone. " +
              "If the package left the store, or the version persists, the run fails safely and " +
              "keeps its restore point — the outcome tells you exactly which."
            : "Every install is verified after it lands (live version, device presence, problem " +
              "codes). Unverified changes are automatically rolled back and the candidate is " +
              "blocked from future offers. Windows Update versions come from catalogue titles; " +
              "a title without a version is refused, never installed blind.";

    public bool IsRefusedPreview { get; }

    public string? RefusedReason { get; }

    private bool _isPreview = true;

    public bool IsPreview
    {
        get => _isPreview;
        private set
        {
            if (Set(ref _isPreview, value))
            {
                RefreshCommands();
            }
        }
    }

    private bool _isRunning;

    public bool IsRunning
    {
        get => _isRunning;
        private set
        {
            if (Set(ref _isRunning, value))
            {
                RefreshCommands();
            }
        }
    }

    private bool _isDone;

    public bool IsDone
    {
        get => _isDone;
        private set
        {
            if (Set(ref _isDone, value))
            {
                RefreshCommands();
            }
        }
    }

    private string _progressText = string.Empty;

    public string ProgressText
    {
        get => _progressText;
        private set => Set(ref _progressText, value);
    }

    private int _progressMax = 1;

    public int ProgressMax
    {
        get => _progressMax;
        private set => Set(ref _progressMax, value);
    }

    private int _progressValue;

    public int ProgressValue
    {
        get => _progressValue;
        private set => Set(ref _progressValue, value);
    }

    private string _outcomeTitle = string.Empty;

    public string OutcomeTitle
    {
        get => _outcomeTitle;
        private set => Set(ref _outcomeTitle, value);
    }

    private string _outcomeDetail = string.Empty;

    public string OutcomeDetail
    {
        get => _outcomeDetail;
        private set => Set(ref _outcomeDetail, value);
    }

    private string _restartStateLine = string.Empty;

    public string RestartStateLine
    {
        get => _restartStateLine;
        private set => Set(ref _restartStateLine, value);
    }

    private string _rollbackHintLine = string.Empty;

    // Update runs that changed anything tell the user where the
    // undo lives (the Drivers page rollback), since this sheet
    // deliberately has no Undo button.
    public string RollbackHintLine
    {
        get => _rollbackHintLine;
        private set => Set(ref _rollbackHintLine, value);
    }

    public ICommand ConfirmCommand { get; private set; } = null!;

    public ICommand CancelRunCommand { get; private set; } = null!;

    public ICommand CloseCommand { get; private set; } = null!;

    public ICommand ViewHistoryCommand { get; private set; } = null!;

    private void InitCommands()
    {
        ConfirmCommand = new RelayCommand(
            _ => StartRun(), _ => IsPreview && !IsRefusedPreview && Included.Count > 0);
        CancelRunCommand = new RelayCommand(_ => CancelRun(), _ => IsRunning);
        CloseCommand = new RelayCommand(_ => RequestClose());
        ViewHistoryCommand = new RelayCommand(
            _ => { ViewHistory?.Invoke(); RequestClose(); },
            _ => IsDone && ViewHistory is not null);
    }

    // The test seam: runs the approval without the window.
    public Task RunAsync() => ExecuteRunAsync(CancellationToken.None);

    private void StartRun()
    {
        if (_runTask is not null)
        {
            return;
        }

        _runCts = new CancellationTokenSource();
        _runTask = ExecuteRunAsync(_runCts.Token);
    }

    private void CancelRun()
    {
        _runCts?.Cancel();
    }

    private async Task ExecuteRunAsync(CancellationToken ct)
    {
        IsPreview = false;
        IsRunning = true;
        ProgressMax = Math.Max(1, _approvals.Count);
        ProgressValue = 0;
        ProgressText = "Starting…";

        var approval = new ActionApproval(
            _template.Id,
            _approvals.Select(a => new ActionTarget(
                a.BrokerId, a.DeviceId, "device", RiskTier.Review,
                0, 0, ExpectedSigner: null, a.AuxJson)).ToList(),
            [],
            [],
            0,
            DateTimeOffset.UtcNow,
            ActionActors.User,
            Guid.NewGuid().ToString("N"));

        var progress = new Progress<ExecutionProgress>(p =>
        {
            ProgressValue = Math.Min(p.Done, ProgressMax);
            ProgressText = p.Total <= 0
                ? p.Current
                : $"{p.Done} of {p.Total} · {p.Current}";
        });

        DispatchOutcome outcome;
        try
        {
            outcome = await _dispatcher().DispatchAsync(approval, null, ct, progress);
        }
        catch (Exception ex)
        {
            outcome = new DispatchOutcome(
                Guid.NewGuid().ToString("N"), _template.Id, BatchStatus.Failed,
                RefusalCode.None, $"Unexpected failure ({ex.GetType().Name}): {ex.Message}",
                [], DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, -1);
        }

        ItemResults.Clear();
        foreach (var item in outcome.Items)
        {
            ItemResults.Add(new SheetOutcomeRow(
                DeviceShortName(item.Target.ExpectedPath),
                item.Status switch
                {
                    ItemStatus.Done => _isRollback ? "Rolled back" : "Updated",
                    ItemStatus.Refused => "Skipped",
                    ItemStatus.Failed => "Failed",
                    ItemStatus.Cancelled => "Cancelled",
                    _ => item.Status.ToString(),
                },
                item.Detail));
        }

        // The D43 title rule: refused/partial/failed outcomes NEVER
        // say "fixed" (or "updated"/"repaired" as a blanket). Only a
        // full Completed earns the blanket verb.
        (OutcomeTitle, OutcomeDetail) = outcome.Status switch
        {
            BatchStatus.Completed => (
                _isRollback ? "Rollback completed" : "Update completed",
                outcome.Detail),
            BatchStatus.Partial => ("Partially completed", outcome.Detail),
            BatchStatus.Refused => ("No changes made", outcome.Detail),
            BatchStatus.Failed => ("Failed safely", outcome.Detail),
            BatchStatus.Cancelled => ("Cancelled", outcome.Detail),
            BatchStatus.Duplicate => ("Already ran", outcome.Detail),
            _ => (outcome.Status.ToString(), outcome.Detail),
        };

        bool rebootPending = outcome.Items.Any(i =>
            i.Detail.Contains("reboot is pending", StringComparison.OrdinalIgnoreCase));
        bool anyDone = outcome.Items.Any(i => i.Status == ItemStatus.Done);
        RestartStateLine = rebootPending
            ? "A restart is pending to finish the driver change. Restart from the Start menu — " +
              "Sentinel re-checks the device afterwards."
            : anyDone
                ? "No restart flagged by the installer. If the device misbehaves, restart anyway."
                : string.Empty;

        RollbackHintLine = !_isRollback && anyDone
            ? "If a new driver misbehaves, roll it back from the Drivers page (select the device → Roll back)."
            : string.Empty;

        IsRunning = false;
        IsDone = true;
    }

    private void RequestClose() => CloseRequested?.Invoke();

    private void RefreshCommands()
    {
        ((RelayCommand)ConfirmCommand).RaiseCanExecuteChanged();
        ((RelayCommand)CancelRunCommand).RaiseCanExecuteChanged();
        ((RelayCommand)ViewHistoryCommand).RaiseCanExecuteChanged();
    }

    private static string SourceLabel(DriverSource source) => source switch
    {
        DriverSource.WindowsUpdate => "Windows Update",
        DriverSource.OemCatalogue => "OEM catalogue",
        DriverSource.VendorLinkOut => "Vendor page (manual)",
        _ => source.ToString(),
    };

    private static string SourceName(DriverSource source) => source switch
    {
        DriverSource.WindowsUpdate => "windows-update",
        DriverSource.OemCatalogue => "oem-catalogue",
        DriverSource.VendorLinkOut => "vendor-link-out",
        _ => source.ToString().ToLowerInvariant(),
    };

    private static string DeviceShortName(string deviceId)
    {
        // Instance IDs are unreadable; the sheet rows already showed
        // friendly names, so outcomes keep the tail for matching.
        int slash = deviceId.LastIndexOf('\\');
        return slash >= 0 && slash + 1 < deviceId.Length
            ? deviceId.Substring(slash + 1)
            : deviceId;
    }
}
