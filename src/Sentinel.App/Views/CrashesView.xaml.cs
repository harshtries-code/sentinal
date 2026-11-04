using System;
using System.ComponentModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using Sentinel.App.ViewModels;

namespace Sentinel.App.Views;

public partial class CrashesView : UserControl
{
    public CrashesView()
    {
        InitializeComponent();
        DataContextChanged += (_, e) =>
        {
            if (e.OldValue is CrashesViewModel oldVm)
            {
                oldVm.PropertyChanged -= OnVmChanged;
                oldVm.HighlightRequested -= OnHighlightRequested;
            }

            if (e.NewValue is CrashesViewModel vm)
            {
                vm.PropertyChanged += OnVmChanged;
                vm.HighlightRequested += OnHighlightRequested;
            }

            Redraw();
        };
        TimelineStrip.SizeChanged += (_, _) => Redraw();
        WeeksCanvas.SizeChanged += (_, _) => Redraw();
        Loaded += (_, _) => Redraw();
    }

    private void OnVmChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(CrashesViewModel.RangeRows)
            or nameof(CrashesViewModel.Weeks)
            or nameof(CrashesViewModel.SelectedRange))
        {
            Redraw();
        }
    }

    // U27: Ask-driven highlight scrolls the target row into view.
    // Selection itself is the VM's (unit-tested); this is pixels.
    private void OnHighlightRequested(CrashesViewModel.CrashRow row)
    {
        EventsGrid.ScrollIntoView(row);
        EventsGrid.Focus();
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is CrashesViewModel vm)
        {
            await vm.RefreshAsync();
        }
    }

    private void Redraw()
    {
        if (DataContext is not CrashesViewModel vm)
        {
            return;
        }

        DrawStrip(vm);
        DrawWeeks(vm);
    }

    private void DrawStrip(CrashesViewModel vm)
    {
        TimelineStrip.Children.Clear();
        double width = TimelineStrip.ActualWidth;
        double height = TimelineStrip.ActualHeight;
        if (width <= 0 || height <= 0)
        {
            return;
        }

        // Baseline.
        TimelineStrip.Children.Add(new Line
        {
            X1 = 4,
            X2 = width - 4,
            Y1 = height / 2,
            Y2 = height / 2,
            Stroke = (Brush)FindResource("BorderBrush"),
            StrokeThickness = 1,
        });

        if (vm.RangeRows.Count == 0)
        {
            return;
        }

        int days = vm.SelectedRange.StartsWith("Last 7", StringComparison.Ordinal) ? 7 : 30;
        var end = DateTime.UtcNow;
        var start = end.AddDays(-days);
        double span = Math.Max(1, (end - start).TotalSeconds);

        foreach (var row in vm.RangeRows)
        {
            double frac = (row.Anchor.TimeUtc - start).TotalSeconds / span;
            frac = Math.Min(1, Math.Max(0, frac));
            var dot = new Ellipse
            {
                Width = 8,
                Height = 8,
                Fill = BrushFor(row.Type),
                ToolTip = $"{row.When} — {row.Type}, Event {row.EventId}",
            };
            Canvas.SetLeft(dot, 4 + frac * (width - 8) - 4);
            Canvas.SetTop(dot, (height / 2) - 4);
            TimelineStrip.Children.Add(dot);
        }
    }

    private void DrawWeeks(CrashesViewModel vm)
    {
        WeeksCanvas.Children.Clear();
        double width = WeeksCanvas.ActualWidth;
        double height = WeeksCanvas.ActualHeight;
        if (width <= 0 || height <= 0 || vm.Weeks.Count == 0)
        {
            return;
        }

        int max = Math.Max(1, vm.Weeks.Max(w => w.Total));
        double slot = width / vm.Weeks.Count;
        double barWidth = Math.Min(48, slot * 0.5);
        double plotHeight = height - 22;

        for (int i = 0; i < vm.Weeks.Count; i++)
        {
            var week = vm.Weeks[i];
            double x = (slot * i) + ((slot - barWidth) / 2);
            double y = plotHeight;
            AddSegment(x, ref y, barWidth, plotHeight, max, week.Crash, CrashesViewModel.TypeCrash);
            AddSegment(x, ref y, barWidth, plotHeight, max, week.Hang, CrashesViewModel.TypeHang);
            AddSegment(x, ref y, barWidth, plotHeight, max, week.Disk, CrashesViewModel.TypeDisk);
            AddSegment(x, ref y, barWidth, plotHeight, max, week.Update, CrashesViewModel.TypeUpdate);
            AddSegment(x, ref y, barWidth, plotHeight, max, week.Hardware, CrashesViewModel.TypeHardware);

            var label = new TextBlock
            {
                Text = week.Label,
                FontSize = 10,
                Foreground = (Brush)FindResource("TextSecondaryBrush"),
            };
            Canvas.SetLeft(label, x);
            Canvas.SetTop(label, plotHeight + 4);
            WeeksCanvas.Children.Add(label);
        }
    }

    private void AddSegment(double x, ref double y, double barWidth, double plotHeight, int max, int count, string type)
    {
        if (count <= 0)
        {
            return;
        }

        double h = Math.Max(3, (count / (double)max) * plotHeight);
        y -= h;
        WeeksCanvas.Children.Add(new Rectangle
        {
            Width = barWidth,
            Height = h,
            Fill = BrushFor(type),
            RadiusX = 2,
            RadiusY = 2,
            ToolTip = $"{type}: {count}",
        });
        Canvas.SetLeft(WeeksCanvas.Children[^1], x);
        Canvas.SetTop(WeeksCanvas.Children[^1], y);
    }

    private Brush BrushFor(string type) => type switch
    {
        CrashesViewModel.TypeHang => (Brush)FindResource("WarningBrush"),
        CrashesViewModel.TypeDisk => (Brush)FindResource("InfoBrush"),
        CrashesViewModel.TypeUpdate => (Brush)FindResource("AccentBrush"),
        // Collected WHEA 19s are corrected (recovered) errors:
        // visible, but softer than a crash or hang.
        CrashesViewModel.TypeHardware => (Brush)FindResource("WarningSoftBrush"),
        _ => (Brush)FindResource("DangerBrush"),
    };
}
