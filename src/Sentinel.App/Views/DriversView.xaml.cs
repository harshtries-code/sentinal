using System.Windows;
using System.Windows.Controls;
using Sentinel.App.Services;
using Sentinel.App.ViewModels;

namespace Sentinel.App.Views;

public partial class DriversView : UserControl
{
    public DriversView()
    {
        InitializeComponent();
    }

    // Refresh re-collects off-UI (WMI is slow); the button
    // disables while the refresh is in flight.
    private void Refresh_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is DriversViewModel model && sender is Button button)
        {
            button.IsEnabled = false;
            var ui = TaskScheduler.FromCurrentSynchronizationContext();
            _ = PageRefresh.Run(
                model.RefreshState,
                DriversViewModel.Collect, model.Apply, "drivers", ui,
                () => button.IsEnabled = true);
        }
    }

    private void ChipAll_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is DriversViewModel model)
        {
            model.ProblemsOnly = false;
        }
    }

    private void ChipProblems_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is DriversViewModel model)
        {
            model.ProblemsOnly = true;
        }
    }

    private void CopyInstance_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is DriversViewModel { SelectedDevice: { } row })
        {
            TryCopy(row.Detail.InstanceId);
        }
    }

    private void CopyDetails_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is DriversViewModel { SelectedDevice: { } row })
        {
            TryCopy(string.Join(
                Environment.NewLine,
                $"Device: {row.Device}",
                $"Status: {row.Status}",
                $"Instance: {row.Detail.InstanceId}",
                $"Driver: {row.Detail.Version} ({row.Detail.Publisher})",
                $"Source: {row.Detail.Source} · {row.Detail.Observed}"));
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

    // D43: update/rollback checks run read-only off-UI inside the
    // ViewModel; these handlers only route the clicks.
    private void CheckUpdates_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is DriversViewModel model)
        {
            model.CheckUpdates();
        }
    }

    private void CancelCheck_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is DriversViewModel model)
        {
            model.CancelCheck();
        }
    }

    private void ReviewUpdate_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is DriversViewModel model)
        {
            model.OpenUpdateSheet();
        }
    }

    private void CheckRollback_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is DriversViewModel model)
        {
            model.CheckRollback();
        }
    }

    private void ReviewRollback_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is DriversViewModel model)
        {
            model.OpenRollbackSheet();
        }
    }

    private void LinkOut_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is DriversViewModel model && sender is Button button)
        {
            model.OpenLink(button.Tag as string);
        }
    }
}
