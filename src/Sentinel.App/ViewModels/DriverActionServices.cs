using Sentinel.Engine.Actions;
using Sentinel.Engine.Drivers;

namespace Sentinel.App.ViewModels;

// Shows the driver sheet. Production opens the modal window;
// tests capture the ViewModel and drive it headless.
public interface IDriverSheetHost
{
    void Show(DriverSheetViewModel sheet);
}

// Everything the Drivers page needs to offer update/rollback
// actions. Null in older constructions = actions unavailable,
// stated honestly (never dead buttons).
public sealed record DriverActionServices(
    Func<ActionDispatcher> Dispatcher,
    IDriverSheetHost Host,
    Func<IDriverOps> Ops,
    ISrClient SrClient,
    Func<DriverBlocklist> Blocklist,
    // Navigates to the History page. Null hides the sheet's
    // View-in-History button (tests, hosts without navigation).
    Action? ViewHistory = null);
