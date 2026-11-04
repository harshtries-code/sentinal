using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace Sentinel.App;

// XAML value converters (P1-06 shared shell).
public sealed class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is Visibility.Visible;
}

public sealed class InverseBoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is not Visibility.Visible;
}

public sealed class BulletPrefixConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        "• " + (value?.ToString() ?? string.Empty);

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;
}

// Maps a display name (page, module, or area title) to the matching
// line-icon geometry from Themes/Icons.xaml. Values that already look
// like a resource key ("IconCpu") pass through; unknown names fall
// back to a plain file icon so a template never renders blank.
public sealed class IconGeometryConverter : IValueConverter
{
    private static readonly Dictionary<string, string> ByName = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Overview"] = "IconHome",
        ["Performance"] = "IconChart",
        ["Storage"] = "IconHardDrive",
        ["Drivers"] = "IconCpu",
        ["Startup"] = "IconPower",
        ["Threats"] = "IconShield",
        ["Defender"] = "IconShield",
        ["Stability"] = "IconActivity",
        ["Crashes"] = "IconAlertTriangle",
        ["History"] = "IconHistory",
        ["Reports"] = "IconFileText",
        ["Events"] = "IconFileText",
        ["Power"] = "IconBattery",
        ["Settings"] = "IconSettings",
    };

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        string? name = (parameter as string) ?? (value as string);
        if (string.IsNullOrWhiteSpace(name))
        {
            return null!;
        }

        string key = name.StartsWith("Icon", StringComparison.Ordinal)
            ? name
            : ByName.TryGetValue(name.Trim(), out string? mapped) ? mapped : "IconFile";
        return Application.Current?.TryFindResource(key) ?? null!;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;
}

public sealed class EqualityConverter : IMultiValueConverter
{
    public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture) =>
        values.Length == 2 && Equals(values[0], values[1]);

    public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
