using System.Collections.Specialized;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using Sentinel.App.ViewModels;

namespace Sentinel.App.Views;

public partial class PerformanceView : UserControl
{
    private PerformanceViewModel? _hooked;

    public PerformanceView()
    {
        InitializeComponent();
        Loaded += (_, _) => RedrawGraph();
        DataContextChanged += (_, _) => HookPoints();
    }

    private void HookPoints()
    {
        if (_hooked is not null)
        {
            _hooked.GraphPoints.CollectionChanged -= OnPointsChanged;
            _hooked = null;
        }

        if (DataContext is PerformanceViewModel model)
        {
            model.GraphPoints.CollectionChanged += OnPointsChanged;
            _hooked = model;
        }

        RedrawGraph();
    }

    private void OnPointsChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        RedrawGraph();
    }

    private void GraphCanvas_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        RedrawGraph();
    }

    // CPU history polyline: samples newest-right, gridlines at
    // 0/half/max, time labels newest-left. Gaps in sampling are
    // drawn as-is (connected) — the caption states the cadence.
    private void RedrawGraph()
    {
        GraphCanvas.Children.Clear();
        if (DataContext is not PerformanceViewModel model
            || model.GraphPoints.Count == 0)
        {
            return;
        }

        double width = GraphCanvas.ActualWidth;
        double height = GraphCanvas.ActualHeight;
        if (width <= 0 || height <= 0)
        {
            return;
        }

        var line = (Brush)FindResource("AccentBrush");
        var grid = (Brush)FindResource("BorderBrush");
        var dim = (Brush)FindResource("TextSecondaryBrush");
        const double padLeft = 34;
        const double padBottom = 16;
        double plotW = width - padLeft - 8;
        double plotH = height - padBottom - 8;
        if (plotW <= 0 || plotH <= 0)
        {
            return;
        }

        double max = Math.Max(10.0, model.GraphPoints.Max(p => p.CpuPercent));
        for (int i = 0; i <= 2; i++)
        {
            double y = 4 + plotH - plotH * i / 2;
            GraphCanvas.Children.Add(new Line
            {
                X1 = padLeft,
                Y1 = y,
                X2 = padLeft + plotW,
                Y2 = y,
                Stroke = grid,
                StrokeThickness = 1,
            });
            var tick = new TextBlock
            {
                Text = $"{max * i / 2:0}%",
                FontSize = 11,
                Foreground = dim,
            };
            Canvas.SetLeft(tick, 0);
            Canvas.SetTop(tick, y - 8);
            GraphCanvas.Children.Add(tick);
        }

        var points = model.GraphPoints;
        var poly = new Polyline
        {
            Stroke = line,
            StrokeThickness = 1.5,
            StrokeLineJoin = PenLineJoin.Round,
        };
        for (int i = 0; i < points.Count; i++)
        {
            double x = points.Count == 1
                ? padLeft + plotW
                : padLeft + plotW * i / (points.Count - 1);
            double y = 4 + plotH - plotH * Math.Min(max, points[i].CpuPercent) / max;
            poly.Points.Add(new Point(x, y));
        }

        GraphCanvas.Children.Add(poly);
        var first = new TextBlock
        {
            Text = points[0].AtUtc.ToLocalTime().ToString("HH:mm"),
            FontSize = 11,
            Foreground = dim,
        };
        Canvas.SetLeft(first, padLeft);
        Canvas.SetTop(first, height - padBottom + 2);
        GraphCanvas.Children.Add(first);
        var last = new TextBlock
        {
            Text = points[points.Count - 1].AtUtc.ToLocalTime().ToString("HH:mm"),
            FontSize = 11,
            Foreground = dim,
        };
        Canvas.SetLeft(last, padLeft + plotW - 32);
        Canvas.SetTop(last, height - padBottom + 2);
        GraphCanvas.Children.Add(last);
    }
}
