using Sentinel.Engine.Actions;

namespace Sentinel.App.ViewModels;

// Shows the Defender scan sheet. Production opens the modal
// window; tests capture the ViewModel and drive it headless.
public interface IDefenderScanSheetHost
{
    void Show(DefenderScanSheetViewModel sheet);
}

// T52: shows the quarantine-restore sheet (same host pattern).
public interface IQuarantineSheetHost
{
    void Show(QuarantineSheetViewModel sheet);
}

// Everything the Threats page needs to offer Defender scans
// and quarantine restore. Null in older constructions =
// confirmation unavailable, stated honestly (the buttons fall
// back to plan-only notes).
public sealed record ThreatActionServices(
    Func<ActionDispatcher> Dispatcher,
    IDefenderScanSheetHost Host,
    // Navigates to the History page. Null hides the sheet's
    // View-in-History button (tests, hosts without navigation).
    Action? ViewHistory = null,
    // Null keeps restore plan-only (older hosts stay honest).
    IQuarantineSheetHost? QuarantineHost = null);
