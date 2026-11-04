using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using Sentinel.App.ViewModels;

namespace Sentinel.App.Views;

public partial class HistoryView : UserControl
{
    public HistoryView()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            if (DataContext is HistoryViewModel vm)
            {
                await vm.RefreshAsync();
            }
        };
    }

    private void KindChip_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button chip && chip.Tag is string kind && DataContext is HistoryViewModel vm)
        {
            vm.SelectedKind = kind;
        }
    }

    private void Event_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button row && row.DataContext is HistoryViewModel.HistoryEvent history
            && DataContext is HistoryViewModel vm)
        {
            vm.SelectedEvent = history;
        }
    }

    private void RunsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (sender is DataGrid grid && grid.SelectedItem is HistoryViewModel.RunRow row
            && DataContext is HistoryViewModel vm)
        {
            vm.JumpToRun(row.Id);
        }
    }

    private void InvestigationsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (sender is DataGrid grid && grid.SelectedItem is HistoryViewModel.InvestigationRow row
            && DataContext is HistoryViewModel vm)
        {
            vm.JumpToInvestigation(row.Id);
        }
    }

    private void ExportJson_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is not HistoryViewModel vm)
        {
            return;
        }

        var dialog = new SaveFileDialog
        {
            Filter = "JSON files (*.json)|*.json",
            FileName = "sentinel-history.json",
        };
        if (dialog.ShowDialog() == true)
        {
            vm.WriteExport(dialog.FileName, "json");
        }
    }

    private void ExportHtml_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is not HistoryViewModel vm)
        {
            return;
        }

        var dialog = new SaveFileDialog
        {
            Filter = "HTML files (*.html)|*.html",
            FileName = "sentinel-history.html",
        };
        if (dialog.ShowDialog() == true)
        {
            vm.WriteExport(dialog.FileName, "html");
        }
    }
}
