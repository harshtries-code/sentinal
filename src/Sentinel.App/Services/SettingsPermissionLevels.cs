using Sentinel.Engine.Actions;

namespace Sentinel.App.Services;

// E30: the dispatcher's view of the L-permissions. Unknown modules
// answer L0 (deny by default). Drivers and Threats are capped at L2
// HERE — a hand-edited settings file, a bug, or an agent cannot
// raise them, because no caller sits below this provider.
public sealed class SettingsPermissionLevels : IPermissionLevels
{
    private readonly Func<SentinelSettings> _current;

    public SettingsPermissionLevels(Func<SentinelSettings> current)
    {
        _current = current;
    }

    public PermissionLevel LevelFor(string module)
    {
        int raw = module switch
        {
            "Cleaner" => _current().CleanerPermission,
            "Drivers" => Math.Min(_current().DriversPermission, 2),
            "Threats" => Math.Min(_current().ThreatsPermission, 2),
            "Startup" => _current().StartupPermission,
            "Performance" => _current().PerformancePermission,
            "System" => _current().SystemPermission,
            _ => 0,
        };
        return (PermissionLevel)Math.Clamp(raw, 0, 3);
    }
}
