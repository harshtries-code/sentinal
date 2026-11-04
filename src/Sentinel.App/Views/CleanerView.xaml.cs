using System.Collections.Specialized;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using Sentinel.App.ViewModels;

namespace Sentinel.App.Views;

public partial class CleanerView : UserControl
{
    private CleanerViewModel? _hooked;

    public CleanerView()
    {
        InitializeComponent();
        Loaded += (_, _) => RedrawTreemap();
        DataContextChanged += (_, _) => HookTreemap();
    }

    private void HookTreemap()
    {
        if (_hooked is not null)
        {
            _hooked.Treemap.CollectionChanged -= OnTreemapChanged;
            _hooked = null;
        }

        if (DataContext is CleanerViewModel model)
        {
            model.Treemap.CollectionChanged += OnTreemapChanged;
            _hooked = model;
        }

        RedrawTreemap();
    }

    private void OnTreemapChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        RedrawTreemap();
    }

    private void TreemapCanvas_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        RedrawTreemap();
    }

    // Treemap paint: L1 prefix boxes subdivided by top files.
    // Same rows as the table (which keeps every box keyboard
    // reachable); a box click filters the table to that file.
    private void RedrawTreemap()
    {
        TreemapCanvas.Children.Clear();
        if (DataContext is not CleanerViewModel model
            || model.Treemap.Count == 0)
        {
            return;
        }

        double width = TreemapCanvas.ActualWidth;
        double height = TreemapCanvas.ActualHeight;
        if (width <= 0 || height <= 0)
        {
            return;
        }

        var soft = (Brush)FindResource("AccentSoftBrush");
        var raised = (Brush)FindResource("SurfaceRaisedBrush");
        var stroke = (Brush)FindResource("BorderBrush");
        var ink = (Brush)FindResource("TextBrush");
        var dim = (Brush)FindResource("TextSecondaryBrush");
        long max = model.Treemap.Max(c => c.Bytes);
        var boxes = TreemapLayout.Layout(
            model.Treemap.Select(c => (c.Key, c.Bytes)).ToList(), width, height);
        foreach (var box in boxes)
        {
            var category = model.Treemap.First(c => c.Key == box.Key);
            bool neutral = category.Key is "Windows" or "Other";
            // P22: category boxes drill the table down to their
            // folders — except "Other", a complement with no prefix.
            bool scopable = category.Key is not "Other";
            var rect = new Rectangle
            {
                Width = Math.Max(0, box.Width - 1),
                Height = Math.Max(0, box.Height - 1),
                Fill = neutral ? raised : soft,
                Opacity = 0.45 + 0.55 * (max <= 0 ? 0 : (double)category.Bytes / max),
                Stroke = stroke,
                StrokeThickness = 1,
                ToolTip = scopable
                    ? $"{category.Key} · {FormatBytes(category.Bytes)} · click to show only these folders"
                    : $"{category.Key} · {FormatBytes(category.Bytes)}",
                Cursor = scopable ? Cursors.Hand : null,
                Tag = category.Key,
            };
            if (scopable)
            {
                rect.MouseLeftButtonUp += TreemapCategory_Click;
            }

            Canvas.SetLeft(rect, box.X);
            Canvas.SetTop(rect, box.Y);
            TreemapCanvas.Children.Add(rect);
            if (box.Width > 90 && box.Height > 48)
            {
                AddLabel(box.X + 6, box.Y + 4, category.Key, 12, true, ink, box.Width - 12);
                AddLabel(
                    box.X + 6, box.Y + 22,
                    $"{FormatBytes(category.Bytes)} · {box.Fraction * 100:0}%", 11, false, dim,
                    box.Width - 12);
            }

            DrawFiles(category, box, stroke, dim);
        }
    }

    private void DrawFiles(
        TreemapCategory category, TreemapRect box, Brush stroke, Brush dim)
    {
        var items = category.TopFiles.Select(f => (f.Name, f.Bytes)).ToList();
        if (category.RestBytes > 0 && category.RestCount > 0)
        {
            items.Add(($" plus {category.RestCount} more", category.RestBytes));
        }

        if (items.Count == 0)
        {
            return;
        }

        double pad = 4;
        double innerW = box.Width - pad * 2;
        double innerH = box.Height - pad * 2 - (box.Height > 48 ? 40 : 0);
        if (innerW <= 20 || innerH <= 16)
        {
            return;
        }

        var subs = TreemapLayout.Layout(items, innerW, innerH);
        foreach (var sub in subs)
        {
            var file = category.TopFiles.FirstOrDefault(f => f.Name == sub.Key);
            var rect = new Rectangle
            {
                Width = Math.Max(0, sub.Width - 1),
                Height = Math.Max(0, sub.Height - 1),
                Fill = Brushes.Transparent,
                Stroke = stroke,
                StrokeThickness = 1,
                ToolTip = file is null
                    ? $"{category.RestCount} more files · {FormatBytes(category.RestBytes)}"
                    : $"{file.Path} · {FormatBytes(file.Bytes)}",
                Cursor = file is null ? null : Cursors.Hand,
                Tag = file?.Name,
            };
            if (file is not null)
            {
                rect.MouseLeftButtonUp += TreemapFile_Click;
            }

            Canvas.SetLeft(rect, box.X + pad + sub.X);
            Canvas.SetTop(rect, box.Y + pad + (box.Height > 48 ? 40 : 0) + sub.Y);
            TreemapCanvas.Children.Add(rect);
            if (sub.Width > 56 && sub.Height > 18)
            {
                AddLabel(
                    box.X + pad + sub.X + 3, box.Y + pad + (box.Height > 48 ? 40 : 0) + sub.Y + 1,
                    sub.Key, 11, false, dim, sub.Width - 6);
            }
        }
    }

    private void AddLabel(
        double x, double y, string text, double size, bool bold, Brush brush, double maxWidth)
    {
        var label = new TextBlock
        {
            Text = text,
            FontSize = size,
            FontWeight = bold ? FontWeights.SemiBold : FontWeights.Normal,
            Foreground = brush,
            MaxWidth = Math.Max(0, maxWidth),
            TextTrimming = TextTrimming.CharacterEllipsis,
        };
        Canvas.SetLeft(label, x);
        Canvas.SetTop(label, y);
        TreemapCanvas.Children.Add(label);
    }

    private void TreemapCategory_Click(object sender, MouseButtonEventArgs e)
    {
        if (sender is Rectangle { Tag: string key }
            && DataContext is CleanerViewModel model)
        {
            model.SetTreemapScope(key);
            e.Handled = true;
        }
    }

    private void MapView_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is CleanerViewModel model)
        {
            model.SetMapView("Map");
        }
    }

    private void TableView_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is CleanerViewModel model)
        {
            model.SetMapView("Table");
        }
    }

    private void RankedGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        // Ranked rows drill exactly like map boxes; "Other" has no
        // prefix and does not scope (SetTreemapScope says so).
        if (RankedGrid.SelectedItem is MapRankRow row
            && DataContext is CleanerViewModel model
            && row.Scopable)
        {
            model.SetTreemapScope(row.Key);
        }
    }

    private void PrevPage_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is CleanerViewModel model)
        {
            model.PrevPage();
        }
    }

    private void NextPage_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is CleanerViewModel model)
        {
            model.NextPage();
        }
    }

    private void ClearScope_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is CleanerViewModel model)
        {
            model.ClearFolderScope();
        }
    }

    private void TreemapFile_Click(object sender, MouseButtonEventArgs e)
    {
        if (sender is Rectangle { Tag: string name }
            && DataContext is CleanerViewModel model)
        {
            model.SearchText = name;
            // File rects sit above the category rect: stop the click
            // here or the category drill-down fires too.
            e.Handled = true;
        }
    }

    private void CopyChecked_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is CleanerViewModel model)
        {
            var paths = model.CheckedEntries().Keys
                .OrderBy(p => p, StringComparer.Ordinal).ToList();
            if (paths.Count > 0)
            {
                TryCopy(string.Join(Environment.NewLine, paths));
            }
        }
    }

    private void ClearChecked_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is CleanerViewModel model)
        {
            model.ClearSelection();
        }
    }

    private void VaultChecked_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is CleanerViewModel model)
        {
            model.BeginVaultAction();
        }
    }

    private void CopyDetailPath_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is CleanerViewModel { SelectedRow: { } row })
        {
            TryCopy(row.Detail.FullPath);
        }
    }

    private void CopyDetailHash_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is CleanerViewModel { SelectedRow: { } row }
            && row.Detail.HashDisplay != "Not requested"
            && row.Detail.HashDisplay != "Not applicable")
        {
            TryCopy(row.Detail.HashDisplay);
        }
    }

    private static void TryCopy(string text)
    {
        try
        {
            Clipboard.SetText(text);
        }
        catch
        {
            // Clipboard busy (RDP/lock) — the text stays visible.
        }
    }

    private void PowerSettings_Click(object sender, RoutedEventArgs e)
    {
        OpenExternal("ms-settings:powersleep");
    }

    private void SystemProperties_Click(object sender, RoutedEventArgs e)
    {
        OpenExternal("sysdm.cpl");
    }

    private static void OpenExternal(string target)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = target,
                UseShellExecute = true,
            });
        }
        catch
        {
            // No shell handler — the note already names the manual path.
        }
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = bytes;
        int unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return $"{value:0.#} {units[unit]}";
    }
}
