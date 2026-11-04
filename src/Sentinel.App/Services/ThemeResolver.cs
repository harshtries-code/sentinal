using Microsoft.Win32;

namespace Sentinel.App.Services;

// U20: maps the Theme setting (+ High Contrast override) to a theme
// dictionary name. "System" follows HKCU AppsUseLightTheme (0 = dark;
// 1/missing/unreadable = light, the Windows default). The registry
// read is injectable so tests pin the mapping without touching HKCU.
public static class ThemeResolver
{
    public static string Resolve(
        string theme,
        bool highContrast,
        Func<int?> readAppsUseLightTheme)
    {
        if (highContrast)
        {
            return "HighContrast";
        }

        if (string.Equals(theme, "Light", StringComparison.OrdinalIgnoreCase))
        {
            return "Light";
        }

        if (string.Equals(theme, "System", StringComparison.OrdinalIgnoreCase))
        {
            int? value;
            try
            {
                value = readAppsUseLightTheme();
            }
            catch
            {
                value = null;
            }

            return value == 0 ? "Dark" : "Light";
        }

        return "Dark";
    }

    public static int? ReadAppsUseLightThemeSetting()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") as int?;
        }
        catch
        {
            return null;
        }
    }
}
