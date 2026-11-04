using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using Sentinel.App.ViewModels;

namespace Sentinel.App.Views;

public partial class ReportsView : UserControl
{
    private double _zoom = 1.0;

    public ReportsView()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            if (DataContext is ReportsViewModel vm && !vm.HasDraft)
            {
                await vm.GenerateAsync();
            }
        };
    }

    private async void Generate_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is ReportsViewModel vm)
        {
            await vm.GenerateAsync();
        }
    }

    private void Format_Checked(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton radio && radio.Tag is string format
            && DataContext is ReportsViewModel vm)
        {
            vm.ExportFormat = format;
        }
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is not ReportsViewModel vm || !vm.HasDraft)
        {
            return;
        }

        bool json = vm.ExportFormat.Equals("JSON", StringComparison.OrdinalIgnoreCase);
        var dialog = new SaveFileDialog
        {
            Filter = json ? "JSON files (*.json)|*.json" : "HTML files (*.html)|*.html",
            FileName = json ? "sentinel-report.json" : "sentinel-report.html",
        };
        if (dialog.ShowDialog() == true)
        {
            vm.WriteExport(dialog.FileName);
        }
    }

    private void ZoomIn_Click(object sender, RoutedEventArgs e) => SetZoom(_zoom + 0.25);

    private void ZoomOut_Click(object sender, RoutedEventArgs e) => SetZoom(_zoom - 0.25);

    private void SetZoom(double zoom)
    {
        _zoom = Math.Min(2.0, Math.Max(0.5, zoom));
        PreviewDoc.LayoutTransform = new ScaleTransform(_zoom, _zoom);
        ZoomLabel.Text = $"{_zoom:0%}";
    }
}
