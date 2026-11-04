using System.Security.Principal;

namespace Sentinel.Engine.Actions;

// Elevation rules, v1 model (05 §9, D41): Sentinel starts
// un-elevated and elevation is per action with a visible reason. v1
// has NO helper process — driver/threat/restore actions run in an
// ELEVATED Sentinel instance (the user relaunches as administrator).
// An unelevated process refuses RequiresElevation templates with
// the relaunch reason; it never attempts, never prompts, never
// partially runs. clean_items_to_vault needs no elevation by design:
// an UnauthorizedAccess on a move maps to an elevation refusal with
// a visible reason and does NOT retry elevated.
public static class ElevationPolicy
{
    public const string RelaunchReason =
        "This action needs administrator approval — relaunch Sentinel as administrator, " +
        "then confirm again. Nothing was done.";

    public const string CleanDeniedReason =
        "Sentinel could not move this file with its current permissions — nothing was done. " +
        "It was left exactly where it was.";

    public static bool IsProcessElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    // Production gate: reads live elevation.
    public static bool TemplateMayRun(ActionTemplate template, out string reason) =>
        TemplateMayRun(template, IsProcessElevated(), out reason);

    // Testable core: the elevation fact is an input.
    public static bool TemplateMayRun(ActionTemplate template, bool isElevated, out string reason)
    {
        if (template.RequiresElevation && !isElevated)
        {
            reason = RelaunchReason;
            return false;
        }

        reason = string.Empty;
        return true;
    }

    // Maps a filesystem failure to the honest outcome: access-denied
    // on a no-elevation template is an elevation refusal, not a
    // generic failure — the user learns WHY, and nothing retried.
    public static bool IsElevationDenial(Exception ex) =>
        ex is UnauthorizedAccessException;
}
