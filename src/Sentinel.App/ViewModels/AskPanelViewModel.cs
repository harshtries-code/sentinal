using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using Sentinel.App.Services;
using Sentinel.Engine.Agent;
using Sentinel.Engine.Ask;

namespace Sentinel.App.ViewModels;

// U27: a prefill request from a page (Crashes "Ask about this").
// IntentHint bypasses keyword classification ("crash"); RowKey
// selects the card to answer about AND the row to highlight.
public sealed record AskAboutRequest(string Question, string? IntentHint, string? RowKey);

public sealed class AskPanelViewModel : ViewModelBase
{
    private readonly Func<AskContext> _contextProvider;
    private readonly IUiDispatcher _dispatcher;
    private readonly Func<bool> _aiEnabled;
    private readonly IAskCloud? _cloud;
    private CancellationTokenSource? _submitCts;
    private int _submitGen;
    private bool _preserveQuestionOnce;
    private string? _pendingIntentHint;
    private string? _pendingRowKey;

    public AskPanelViewModel(
        Func<AskContext> contextProvider, IUiDispatcher dispatcher, Func<bool>? aiEnabled = null,
        IAskCloud? cloud = null)
    {
        _contextProvider = contextProvider;
        _dispatcher = dispatcher;
        _aiEnabled = aiEnabled ?? (() => true);
        _cloud = cloud;
        ToggleCommand = new RelayCommand(_ => IsOpen = !IsOpen);
        SubmitCommand = new RelayCommand(_ => Submit(), _ => !IsBusy);
        ChipCommand = new RelayCommand(p => UseChip(p as string ?? string.Empty), _ => !IsBusy);
        CloseCommand = new RelayCommand(_ => Close(), _ => IsOpen);
        ActionCommand = new RelayCommand(action =>
        {
            if (action is not AskAction ask)
            {
                return;
            }

            if (ask.Kind == "StartBalancedScan")
            {
                StartScanRequested?.Invoke();
            }
            else if (ask.Kind == "OpenPage"
                && int.TryParse(ask.Target, out int page))
            {
                NavigateToPage?.Invoke(page);
            }
            else if (ask.Kind == "OpenPage")
            {
                // RowKey (when set) rides along: the subscriber
                // navigates first, then highlights within the page.
                NavigateToAskPage?.Invoke(ask);
            }
        });
    }

    public event Action? StartScanRequested;

    public event Action<int>? NavigateToPage;

    // U27: OpenPage actions whose target is a page NAME (not an
    // index). Carries the full action so the shell can also route
    // RowKey to the target page's highlight.
    public event Action<AskAction>? NavigateToAskPage;

    // U27: focus-return seam. Raised when the panel closes; the
    // window restores focus to the opener it captured on open.
    public event Action? Closed;

    public ICommand ToggleCommand { get; }

    public ICommand SubmitCommand { get; }

    public ICommand ChipCommand { get; }

    public ICommand CloseCommand { get; }

    public ICommand ActionCommand { get; }

    public IReadOnlyList<string> SuggestedChips => AskEngine.SuggestedChips;

    private bool _isOpen;

    public bool IsOpen
    {
        get => _isOpen;
        set
        {
            if (Set(ref _isOpen, value))
            {
                if (value)
                {
                    // Fresh panel on every open — but a prefill
                    // request preserves its question (Trigger A/B:
                    // stale answers never survive an open).
                    if (!_preserveQuestionOnce)
                    {
                        Question = string.Empty;
                    }

                    _preserveQuestionOnce = false;
                    Answer = null;
                    RefreshCloudStatus(null);
                }
                else
                {
                    // Trigger C: closing cancels the in-flight
                    // submit; its completion is dropped by the
                    // generation check even if it already finished.
                    // Busy clears here too — otherwise a cancelled
                    // submit wedges the panel (Submit/Chip stay
                    // disabled) after the next open.
                    _submitCts?.Cancel();
                    _submitGen++;
                    IsBusy = false;
                    Closed?.Invoke();
                }

                ((RelayCommand)SubmitCommand).RaiseCanExecuteChanged();
                ((RelayCommand)ChipCommand).RaiseCanExecuteChanged();
                ((RelayCommand)CloseCommand).RaiseCanExecuteChanged();
            }
        }
    }

    // U27: prefill entry point. Preserves the question across the
    // open-clear, and arms the one-shot intent hint + row key the
    // next Submit consumes.
    public void OpenWithQuestion(string question, string? intentHint = null, string? rowKey = null)
    {
        _pendingIntentHint = intentHint;
        _pendingRowKey = rowKey;
        _preserveQuestionOnce = true;
        Question = question;
        IsOpen = true;
    }

    public void Close()
    {
        IsOpen = false;
    }

    private string _question = string.Empty;

    public string Question
    {
        get => _question;
        set => Set(ref _question, value);
    }

    private AskAnswer? _answer;

    public AskAnswer? Answer
    {
        get => _answer;
        set
        {
            if (Set(ref _answer, value))
            {
                Raise(nameof(ActionVisible));
                Raise(nameof(ActionLabel));
                Raise(nameof(StatusLabel));
                Raise(nameof(HasDetail));
            }
        }
    }

    private bool _isBusy;

    public bool IsBusy
    {
        get => _isBusy;
        set
        {
            if (Set(ref _isBusy, value))
            {
                ((RelayCommand)SubmitCommand).RaiseCanExecuteChanged();
                ((RelayCommand)ChipCommand).RaiseCanExecuteChanged();
            }
        }
    }

    public string StatusLabel => Answer switch
    {
        null => string.Empty,
        { Refused: true } => "I only know your PC",
        // U27: AI-off is its own state now, never "general
        // guidance" (C6). Sources are labelled on every answer.
        { AiDisabled: true } => "AI is off — turn it on in Settings",
        { FromCloud: true } => "Grounded in your findings (cloud explanation)",
        { IsGeneralGuidance: true } => "General guidance — not backed by scan evidence",
        _ => "Grounded in your PC data (deterministic)",
    };

    public bool ActionVisible => Answer?.Action is not null;

    public string ActionLabel => Answer?.Action?.Label ?? string.Empty;

    public bool HasDetail => !string.IsNullOrEmpty(Answer?.Detail);

    private string _cloudStatus = "Cloud: no key saved";

    // U27: real cloud status (R37): key presence + last outcome.
    public string CloudStatus
    {
        get => _cloudStatus;
        private set => Set(ref _cloudStatus, value);
    }

    public void Submit()
    {
        string question = Question.Trim();
        if (question.Length == 0 || IsBusy)
        {
            return;
        }

        if (!_aiEnabled())
        {
            Answer = new AskAnswer(
                "AI is off — turn it on in Settings, group B.",
                [], null, false, false, null, false, true);
            return;
        }

        string? intentHint = _pendingIntentHint;
        string? rowKey = _pendingRowKey;
        _pendingIntentHint = null;
        _pendingRowKey = null;

        _submitCts?.Cancel();
        _submitCts = new CancellationTokenSource();
        CancellationToken token = _submitCts.Token;
        int gen = ++_submitGen;
        IsBusy = true;
        Answer = null;
        _ = Task.Run(async () =>
        {
            AskAnswer answer;
            string? cloudOutcome = null;
            try
            {
                AskContext context = _contextProvider();
                token.ThrowIfCancellationRequested();
                var det = AskEngine.Answer(question, context, intentHint, rowKey);
                answer = det;
                if (ShouldEscalate(det) && _cloud is not null)
                {
                    try
                    {
                        AskCloudResult cloud = await _cloud
                            .ExplainAsync(question, context, token)
                            .ConfigureAwait(false);
                        token.ThrowIfCancellationRequested();
                        answer = CloudAnswer(cloud, context);
                        cloudOutcome = $"answered · sent {cloud.SentBytes / 1024.0:F1} KB";
                    }
                    catch (OperationCanceledException)
                    {
                        throw;
                    }
                    catch (Exception ex) when (
                        ex is ModelUnavailableException || ex is BudgetExhaustedException)
                    {
                        // Outage honesty WITH utility: the failure
                        // is the fact, the deterministic guidance
                        // survives as expandable detail.
                        string reason = ex is BudgetExhaustedException ? "time budget" : ex.Message;
                        answer = new AskAnswer(
                            AskEngine.Fact($"Couldn't reach the cloud model ({reason}). Your scan results are intact — try asking again."),
                            det.Evidence, det.Action, true, false,
                            "What I can still tell you: " + det.Fact);
                        cloudOutcome = $"last call failed ({reason})";
                    }
                }
            }
            catch (OperationCanceledException)
            {
                return; // Closed mid-flight (Trigger C): post nothing.
            }
            catch (Exception ex)
            {
                answer = new AskAnswer(
                    "I couldn't reach your PC data just now (" + ex.GetType().Name + ").",
                    [], null, true, false);
            }

            string? outcome = cloudOutcome;
            _dispatcher.Post(() =>
            {
                if (gen != _submitGen)
                {
                    return; // Stale completion: a newer submit or close won.
                }

                if (outcome is not null)
                {
                    RefreshCloudStatus(outcome);
                }

                Answer = answer;
                IsBusy = false;
            });
        });
    }

    // Cloud explains ONLY what deterministic cannot ground: general
    // guidance with no action attached. Refusals, AI-off, grounded
    // answers, and no-key setups never escalate.
    private bool ShouldEscalate(AskAnswer det)
    {
        return det is { Refused: false, IsGeneralGuidance: true, Action: null }
            && _cloud?.CanExplain == true;
    }

    private static AskAnswer CloudAnswer(AskCloudResult cloud, AskContext context)
    {
        var chips = new List<AskEvidenceChip>();
        foreach (var f in context.FindingDigests.Take(AskEngine.MaxChips))
        {
            chips.Add(new AskEvidenceChip(
                $"finding {f.Number}", $"{f.Status}: {AskEngine.Fact(f.Observation)}"));
        }

        return new AskAnswer(
            AskEngine.Fact(cloud.Text), chips, null, false, false, cloud.Text, true, false);
    }

    private void RefreshCloudStatus(string? outcome)
    {
        if (_cloud?.CanExplain != true)
        {
            CloudStatus = "Cloud: no key saved";
        }
        else if (outcome is null)
        {
            CloudStatus = "Cloud: ready";
        }
        else
        {
            CloudStatus = "Cloud: " + outcome;
        }
    }

    public void UseChip(string chip)
    {
        if (IsBusy)
        {
            return;
        }

        Question = chip;
        Submit();
    }
}
