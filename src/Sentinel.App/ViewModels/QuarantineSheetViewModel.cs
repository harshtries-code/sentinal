using System.Windows.Input;
using Sentinel.Engine.Actions;
using Sentinel.Engine.Policy;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.App.ViewModels;

// T52: the quarantine-restore sheet — Preview → Running → Done
// for ONE item. States the exact command, the target identity,
// and the reversibility boundary (Sentinel cannot re-quarantine;
// only a Defender scan re-detects). Confirm requires the
// understanding checkbox: restoring releases the file back to
// its recorded location.
public sealed class QuarantineSheetViewModel : ViewModelBase
{
    private readonly ActionTemplate _template;
    private readonly Func<ActionDispatcher> _dispatcher;
    private readonly QuarantineRestorePlan _plan;
    private CancellationTokenSource? _runCts;
    private Task? _runTask;

    public QuarantineSheetViewModel(
        QuarantineRestorePlan plan,
        string explanation,
        ActionTemplate template,
        Func<ActionDispatcher> dispatcher)
    {
        _plan = plan;
        _template = template;
        _dispatcher = dispatcher;
        ExplanationLine = explanation;
        IsRefusedPreview = !plan.Ready;
        RefusedReason = plan.Ready ? null : plan.Detail;
        ConfirmCommand = new RelayCommand(
            _ => StartRun(), _ => IsPreview && !IsRefusedPreview && Understood);
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

    public string TargetLine => $"Restore '{_plan.Name}'";

    public string CommandLine => _plan.CommandLine;

    public string ExplanationLine { get; }

    public string ElevationLine => ElevationPolicy.IsProcessElevated()
        ? "Running as administrator — elevation verified for this run."
        : ElevationPolicy.RelaunchReason;

    public string ReversibilityLine =>
        "Restoring releases this file back to its recorded location. Sentinel cannot put it " +
        "back into quarantine — if it is still a threat, only a Defender scan will detect it again.";

    private bool _understood;

    public bool Understood
    {
        get => _understood;
        set
        {
            if (Set(ref _understood, value))
            {
                RefreshCommands();
            }
        }
    }

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
        ProgressText = "Requesting the restore…";

        var aux = new QuarantineRestoreAux(_plan.Name);
        var approval = new ActionApproval(
            _template.Id,
            [new ActionTarget("quarantine:0", _plan.Name, "quarantine", RiskTier.Review,
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
            BatchStatus.Completed => ("Restore done",
                outcome.Items.FirstOrDefault()?.Detail ?? outcome.Detail),
            BatchStatus.Refused => ("No restore done", outcome.Detail),
            BatchStatus.Failed => ("Restore failed",
                outcome.Items.FirstOrDefault()?.Detail ?? outcome.Detail),
            BatchStatus.Cancelled => ("Cancelled", outcome.Detail),
            BatchStatus.Duplicate => ("Already ran", outcome.Detail),
            BatchStatus.Partial => ("Restore done", outcome.Detail),
            _ => (outcome.Status.ToString(), outcome.Detail),
        };

        IsRunning = false;
        IsDone = true;
    }

    private void RequestClose() => CloseRequested?.Invoke();

    private void RefreshCommands()
    {
        ((RelayCommand)ConfirmCommand).RaiseCanExecuteChanged();
        ((RelayCommand)CancelRunCommand).RaiseCanExecuteChanged();
        ((RelayCommand)CloseCommand).RaiseCanExecuteChanged();
        ((RelayCommand)ViewHistoryCommand).RaiseCanExecuteChanged();
    }
}
