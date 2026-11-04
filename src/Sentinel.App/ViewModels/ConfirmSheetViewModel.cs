using System.Collections.ObjectModel;
using System.Windows.Input;
using Sentinel.App.Services;
using Sentinel.Engine.Actions;

namespace Sentinel.App.ViewModels;

public sealed record SheetOutcomeRow(string Name, string StatusText, string Detail);

// E33: the Confirm Sheet — the last human gate before any mutation.
// Three states (Preview → Running → Done), one exact file list, one
// Confirm button for exactly that list, honest progress with real
// cancellation, and an Undo button that exists ONLY when every moved
// item carries a verified restore record. There is deliberately no
// "clean all" path: the approval is built from Preview.Included and
// nothing else.
public sealed class ConfirmSheetViewModel : ViewModelBase
{
    private readonly CleanPreview _preview;
    private readonly ActionTemplate _template;
    private readonly Func<ActionDispatcher> _dispatcher;
    private readonly IUndoService _undo;
    private readonly IReadOnlyList<string> _scopeExcluded;
    private CancellationTokenSource? _runCts;
    private Task? _runTask;
    private IReadOnlyList<ItemOutcome> _lastItems = [];

    public ConfirmSheetViewModel(
        CleanPreview preview,
        ActionTemplate template,
        Func<ActionDispatcher> dispatcher,
        IUndoService undo,
        IReadOnlyList<string> scopeExcluded)
    {
        _preview = preview;
        _template = template;
        _dispatcher = dispatcher;
        _undo = undo;
        _scopeExcluded = scopeExcluded;

        foreach (var item in preview.Included)
        {
            Included.Add(item);
        }

        foreach (var item in preview.Excluded)
        {
            Excluded.Add(item);
        }

        ConfirmCommand = new RelayCommand(_ => StartRun(), _ => IsPreview && !IsRefusedPreview);
        CancelRunCommand = new RelayCommand(_ => CancelRun(), _ => IsRunning);
        CloseCommand = new RelayCommand(_ => RequestClose());
        UndoCommand = new RelayCommand(_ => StartUndo(), _ => UndoAvailable && !IsUndoRunning);
        ViewHistoryCommand = new RelayCommand(
            _ => { ViewHistory?.Invoke(); RequestClose(); },
            _ => IsDone && ViewHistory is not null);
    }

    public event Action? CloseRequested;

    // E37: wires the outcome to the History page. Set by the host
    // (MainViewModel); null hides the button (tests, L3 runs).
    public Action? ViewHistory { get; set; }

    public bool HasViewHistory => ViewHistory is not null;

    public CleanPreview Preview => _preview;

    public ObservableCollection<CleanPreviewItem> Included { get; } = [];

    public ObservableCollection<CleanExcludedItem> Excluded { get; } = [];

    public ObservableCollection<SheetOutcomeRow> ItemResults { get; } = [];

    public string ActionTitle => _template.Title;

    public string CountLine =>
        $"{_preview.Included.Count} file(s) · {_preview.TotalText}";

    public string AsOfLine =>
        $"Previewed {_preview.PreviewedUtc.LocalDateTime:g} · scan generation {_preview.Generation}";

    public string ScopeLine =>
        _preview.ScopeRoots.Count == 0
            ? "Scope: none recorded — the run will refuse every item."
            : "Scope: " + ScopeSummary(_preview.ScopeRoots);

    public string ExcludedLine =>
        _preview.Excluded.Count == 0
            ? "Everything selected is included."
            : $"{_preview.Excluded.Count} selected entr(ies) excluded — see reasons.";

    public bool HasExcluded => _preview.Excluded.Count > 0;

    public string BackupLine =>
        "Backup: a Sentinel Vault record for every file (per-volume store, reviewed, never auto-deleted). " +
        "Nothing is deleted — moved bytes stay restorable until you review them.";

    public string PermissionLine =>
        "Permission: Cleaner L2 — Fix with approval. This confirmation approves exactly the files listed above.";

    public string ElevationLine =>
        _template.RequiresElevation
            ? "Needs administrator approval (elevation helper required)."
            : "Needs no administrator approval.";

    public string LimitationsLine =>
        "Same-volume moves free no disk space — retained bytes are reported separately, never as freed space. " +
        "Every file is re-checked at execution (locks, changes, protection); changed files are skipped, not forced. " +
        "A restore that finds your data already at the path restores beside it — your data is never overwritten.";

    public bool IsRefusedPreview => _preview.RefusedReason is not null;

    public string? RefusedReason => _preview.RefusedReason;

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

    private bool _undoAvailable;

    public bool UndoAvailable
    {
        get => _undoAvailable;
        private set
        {
            if (Set(ref _undoAvailable, value))
            {
                RefreshCommands();
            }
        }
    }

    private bool _isUndoRunning;

    public bool IsUndoRunning
    {
        get => _isUndoRunning;
        private set
        {
            if (Set(ref _isUndoRunning, value))
            {
                RefreshCommands();
            }
        }
    }

    private string _undoLine = string.Empty;

    public string UndoLine
    {
        get => _undoLine;
        private set => Set(ref _undoLine, value);
    }

    public ICommand ConfirmCommand { get; }

    public ICommand CancelRunCommand { get; }

    public ICommand CloseCommand { get; }

    public ICommand UndoCommand { get; }

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

    private void CancelRun()
    {
        _runCts?.Cancel();
    }

    private async Task ExecuteRunAsync(CancellationToken ct)
    {
        IsPreview = false;
        IsRunning = true;
        ProgressMax = Math.Max(1, _preview.Included.Count);
        ProgressValue = 0;
        ProgressText = "Starting…";

        var approval = new ActionApproval(
            _template.Id,
            _preview.Included.Select(i => new ActionTarget(
                i.BrokerId, i.Path, "file", i.Tier,
                i.SizeBytes, i.MtimeUtcTicks, ExpectedSigner: null)).ToList(),
            _preview.ScopeRoots,
            _scopeExcluded,
            _preview.Generation,
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
            // The dispatcher never throws by contract; this is the
            // backstop if a future executor leaks one past it.
            outcome = new DispatchOutcome(
                Guid.NewGuid().ToString("N"), _template.Id, BatchStatus.Failed,
                RefusalCode.None, $"Unexpected failure ({ex.GetType().Name}): {ex.Message}",
                [], DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, -1);
        }

        _lastItems = outcome.Items;
        ItemResults.Clear();
        foreach (var item in outcome.Items)
        {
            ItemResults.Add(new SheetOutcomeRow(
                System.IO.Path.GetFileName(item.Target.ExpectedPath),
                item.Status switch
                {
                    ItemStatus.Done => "Moved to Vault",
                    ItemStatus.Refused => "Skipped",
                    ItemStatus.Failed => "Failed",
                    ItemStatus.Cancelled => "Cancelled",
                    _ => item.Status.ToString(),
                },
                item.Detail + (item.VaultRef is null ? string.Empty : $" (Vault {item.VaultRef})")));
        }

        (OutcomeTitle, OutcomeDetail) = outcome.Status switch
        {
            BatchStatus.Completed => ("Completed", outcome.Detail),
            BatchStatus.Partial => ("Partially completed", outcome.Detail),
            BatchStatus.Refused => ("Refused", outcome.Detail),
            BatchStatus.Failed => ("Failed safely", outcome.Detail),
            BatchStatus.Cancelled => ("Cancelled", outcome.Detail),
            BatchStatus.Duplicate => ("Already ran", outcome.Detail),
            _ => (outcome.Status.ToString(), outcome.Detail),
        };

        // The E33 gating rule: Undo is offered only when at least one
        // item moved AND every moved item carries a verified restore
        // record. Anything else (refusals, failures, unverified) keeps
        // the button gone — never a promise without the record.
        var moved = outcome.Items.Where(i => i.Status == ItemStatus.Done).ToList();
        UndoAvailable = moved.Count > 0 && moved.All(i => i.UndoAvailable && i.VaultRef is not null);

        IsRunning = false;
        IsDone = true;
    }

    private async void StartUndo()
    {
        await UndoAsync();
    }

    // Test seam: the command routes here, so tests await the same path.
    public async Task UndoAsync()
    {
        if (IsUndoRunning || !UndoAvailable)
        {
            return;
        }

        IsUndoRunning = true;
        UndoLine = "Restoring…";
        var refs = _lastItems
            .Where(i => i.Status == ItemStatus.Done && i.UndoAvailable && i.VaultRef is not null)
            .Select(i => i.VaultRef!)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        IReadOnlyList<UndoItemResult> results;
        try
        {
            results = await _undo.RestoreAsync(refs, CancellationToken.None);
        }
        catch (Exception ex)
        {
            UndoLine = $"Restore failed ({ex.GetType().Name}): {ex.Message} — the vault still holds the bytes.";
            IsUndoRunning = false;
            return;
        }

        int ok = results.Count(r => r.Restored);
        if (ok == results.Count && results.Count > 0)
        {
            UndoLine = ok == 1
                ? $"Restored 1 file to its original place{(results[0].RestoredPath is null ? "." : ": " + results[0].RestoredPath)}"
                : $"Restored {ok} files to their original places.";
        }
        else if (ok > 0)
        {
            UndoLine = $"Restored {ok} of {results.Count} — " +
                string.Join("; ", results.Where(r => !r.Restored).Select(r => r.Detail));
        }
        else if (results.Count == 0)
        {
            UndoLine = "Nothing to restore.";
        }
        else
        {
            UndoLine = "Restore failed — " +
                string.Join("; ", results.Select(r => r.Detail));
        }

        UndoAvailable = false;
        IsUndoRunning = false;
    }

    private void RequestClose() => CloseRequested?.Invoke();

    private void RefreshCommands()
    {
        ((RelayCommand)ConfirmCommand).RaiseCanExecuteChanged();
        ((RelayCommand)CancelRunCommand).RaiseCanExecuteChanged();
        ((RelayCommand)UndoCommand).RaiseCanExecuteChanged();
        ((RelayCommand)ViewHistoryCommand).RaiseCanExecuteChanged();
    }

    private static string ScopeSummary(IReadOnlyList<string> roots)
    {
        if (roots.Count <= 3)
        {
            return string.Join("; ", roots);
        }

        return string.Join("; ", roots.Take(3)) + $" (+{roots.Count - 3} more)";
    }

}
