using System.Windows;
using Sentinel.App.ViewModels;

namespace Sentinel.App.Views;

public sealed class WindowDriverSheetHost : IDriverSheetHost
{
    public void Show(DriverSheetViewModel sheet)
    {
        var window = new DriverSheetWindow(sheet)
        {
            Owner = Application.Current?.MainWindow,
        };
        window.ShowDialog();
    }
}
