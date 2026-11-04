using System.Windows;
using Sentinel.App.ViewModels;

namespace Sentinel.App.Views;

public sealed class WindowDefenderScanSheetHost : IDefenderScanSheetHost
{
    public void Show(DefenderScanSheetViewModel sheet)
    {
        var window = new DefenderScanSheetWindow(sheet)
        {
            Owner = Application.Current?.MainWindow,
        };
        window.ShowDialog();
    }
}
