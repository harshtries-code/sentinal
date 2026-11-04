using System.Windows.Input;
using Sentinel.Engine.Actions;
using Sentinel.Engine.Policy;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.App.ViewModels;

// T50: the Defender scan sheet — Preview → Running → Done for ONE
// scan (scans run minutes to hours; batching them is nonsense).
// The sheet states the exact command, the elevation need, and the
// Defender-owned remediation warning; offline scans additionally
// require the restart acknowledgement checkbox. Cancellation stops
// Sentinel waiting — a launched Defender scan continues (the
// outcome says so; killing someone else's scan would be worse).
public sealed class DefenderScanSheetViewModel : ViewModelBase
{
    private readonly ActionTemplate _template;
    private readonly Func<ActionDispatcher> _dispatcher;
    private readonly DefenderScanRequest _request;
    private readonly DefenderScanPlan _plan;
    private CancellationTokenSource? _runCts;
    private Task? _runTask;

    public DefenderScanSheetViewModel(
        DefenderScanRequest request,
        DefenderScanPlan plan,
        ActionTemplate template,
        Func<ActionDispatcher> dispatcher)
    {
        _request = request;
        _plan = plan;
        _template = template;
        _dispatcher = dispatcher;
        IsRefusedPreview = !plan.Ready;
        RefusedReason = plan.Ready ? null : plan.Detail;
        ConfirmCommand = new RelayCommand(
            _ => StartRun(), _ => IsPreview && !IsRefusedPreview && (!NeedsRestartAck || RestartAcknowledged));
        CancelRunCommand = new RelayCommand(_ => CancelRun(), _ => IsRunning);
        CloseCommand = new RelayCommand(_ => RequestClose());
        ViewHistoryCommand = new RelayCommand(
            _ => { ViewHistory?.Invoke(); RequestClose(); },
            _ => IsDone && ViewHistory is not null);
    }

    public event Action? CloseRequested;

    public Action? ViewHistory { get; set; }

    public bool HasViewHistory => ViewHistory is not null;

    public string ActionTitle => _template.Title;

    public string KindLine => $"Defender {_plan.KindLabel}";

    public string CommandLine => _plan.CommandLine;

    public string DetailLine => _plan.Detail;

    public bool NeedsRestartAck => _request.Kind == DefenderScanKind.Offline;

    private bool _restartAcknowledged;

    public bool RestartAcknowledged
    {
        get => _restartAcknowledged;
        set
        {
            if (Set(ref _restartAcknowledged, value))
            {
                RefreshCommands();
            }
        }
    }

    public string ElevationLine => ElevationPolicy.IsProcessElevated()
        ? "Running as administrator — elevation verified for this run."
        : ElevationPolicy.RelaunchReason;

    public string RemediationLine =>
        "Defender may quarantine what it finds under its own protection policy. " +
        "Sentinel only asks for the scan and imports the results — it removes nothing itself.";

    public string ProgressLine =>
        "Progress shows in Windows Security while the scan runs. Quick scans take minutes; " +
        "full scans can take hours.";

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

    public ICommand ConfirmCommand { get; }

    public ICommand CancelRunCommand { get; }

    public ICommand CloseCommand { get; }

    public ICommand ViewHistoryCommand { get; }

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

    private void CancelRun() => _runCts?.Cancel();

    private async Task ExecuteRunAsync(CancellationToken ct)
    {
        IsPreview = false;
        IsRunning = true;
        ProgressText = "Requesting the scan…";

        var aux = new DefenderScanAux(
            _request.Kind.ToString().ToLowerInvariant(),
            _request.Kind == DefenderScanKind.Folder ? _request.Path : null,
            _request.Kind == DefenderScanKind.Offline && RestartAcknowledged);
        var approval = new ActionApproval(
            _template.Id,
            [new ActionTarget("scan:0", TargetPath(), "scan", RiskTier.Review,
                0, 0, ExpectedSigner: null, aux.ToJson())],
            [],
            [],
            0,
            DateTimeOffset.UtcNow,
            ActionActors.User,
            Guid.NewGuid().ToString("N"));

        var progress = new Progress<ExecutionProgress>(p => ProgressText =
            $"Requested… {p.Current}");

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

        (OutcomeTitle, OutcomeDetail) = outcome.Status switch
        {
            BatchStatus.Completed => ("Scan requested",
                outcome.Items.FirstOrDefault()?.Detail ?? outcome.Detail),
            BatchStatus.Refused => ("No scan started", outcome.Detail),
            BatchStatus.Failed => ("Scan failed",
                outcome.Items.FirstOrDefault()?.Detail ?? outcome.Detail),
            BatchStatus.Cancelled => ("Cancelled", outcome.Detail),
            BatchStatus.Duplicate => ("Already ran", outcome.Detail),
            BatchStatus.Partial => ("Scan requested", outcome.Detail),
            _ => (outcome.Status.ToString(), outcome.Detail),
        };

        IsRunning = false;
        IsDone = true;
    }

    private string TargetPath() => _request.Kind switch
    {
        DefenderScanKind.Folder => _request.Path ?? "folder scan",
        DefenderScanKind.Offline => "offline scan",
        DefenderScanKind.Quick => "quick scan",
        DefenderScanKind.Full => "full scan",
        _ => "scan",
    };

    private void RequestClose() => CloseRequested?.Invoke();

    private void RefreshCommands()
    {
        ((RelayCommand)ConfirmCommand).RaiseCanExecuteChanged();
        ((RelayCommand)CancelRunCommand).RaiseCanExecuteChanged();
        ((RelayCommand)ViewHistoryCommand).RaiseCanExecuteChanged();
    }
}
