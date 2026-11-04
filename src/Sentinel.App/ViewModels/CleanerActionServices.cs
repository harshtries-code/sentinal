using Sentinel.App.Services;
using Sentinel.Engine.Actions;

namespace Sentinel.App.ViewModels;

// Shows the Confirm Sheet. Production opens the modal window;
// tests capture the ViewModel and drive it headless.
public interface IConfirmSheetHost
{
    void Show(ConfirmSheetViewModel sheet);
}

// Everything the Cleaner page needs to offer vault actions. Null in
// older constructions = actions unavailable, stated honestly.
public sealed record CleanerActionServices(
    Func<ActionDispatcher> Dispatcher,
    IUndoService Undo,
    IConfirmSheetHost Host,
    IReadOnlyList<string> ScopeExcluded,
    // E37: navigates to the History page. Null hides the sheet's
    // View-in-History button (tests, hosts without navigation).
    Action? ViewHistory = null);
